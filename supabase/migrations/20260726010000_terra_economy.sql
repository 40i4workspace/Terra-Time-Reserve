-- Phase 2: internal time-denominated economics. These records never create a withdrawal path.
create type public.terra_asset_code as enum ('GOLD','OIL','SILVER','NATGAS','BTC','USD','JPY','PLATINUM','SP500','APPLE');
create type public.terra_position_side as enum ('LONG','SHORT');
create type public.terra_position_status as enum ('OPEN','CLOSED','LIQUIDATED');
create type public.terra_pension_status as enum ('ACTIVE','MATURED','CLOSED');

create table public.terra_rbh_oracle (
 id bigint generated always as identity primary key, observed_rbh_usd numeric(150,72) not null check(observed_rbh_usd > 0),
 baseline_rbh_usd numeric(150,72) not null default 30 check(baseline_rbh_usd > 0), source text not null check(length(source) between 3 and 120), observed_at timestamptz not null default now(), submitted_by text not null
);
create table public.terra_asset_quotes (
 id bigint generated always as identity primary key, asset public.terra_asset_code not null, source_price_usd numeric(150,72) not null check(source_price_usd > 0),
 rbh_oracle_id bigint not null references public.terra_rbh_oracle(id), trr_per_unit numeric(150,72) not null check(trr_per_unit > 0),
 source text not null check(length(source) between 3 and 120), quoted_at timestamptz not null default now(), unique(asset, quoted_at)
);

create table public.terra_stakes (
 id uuid primary key default gen_random_uuid(), owner_user_id uuid not null references auth.users(id), principal_trr numeric(150,72) not null check(principal_trr > 0),
 term_days smallint not null check(term_days in (30,90,180,365)), power_multiplier numeric(10,2) not null check(power_multiplier in (1,2,4)), reward_trr numeric(150,72) not null check(reward_trr >= 0),
 started_at timestamptz not null default now(), matures_at timestamptz not null, claimed_at timestamptz, cancelled_at timestamptz,
 check (not (claimed_at is not null and cancelled_at is not null))
);
create table public.terra_stake_partitions (stake_id uuid not null references public.terra_stakes(id) on delete restrict, partition_id uuid not null references public.terra_partitions(id) on delete restrict, primary key(stake_id,partition_id));
-- Active collateral exclusivity is enforced by the private API transaction locks.

create table public.terra_positions (
 id uuid primary key default gen_random_uuid(), owner_user_id uuid not null references auth.users(id), asset public.terra_asset_code not null, side public.terra_position_side not null,
 leverage smallint not null check(leverage in (1,2,5,10,20)), margin_trr numeric(150,72) not null check(margin_trr > 0), notional_trr numeric(150,72) not null check(notional_trr > 0),
 entry_trr_per_unit numeric(150,72) not null check(entry_trr_per_unit > 0), units numeric(150,72) not null check(units > 0), liquidation_price_trr numeric(150,72) not null check(liquidation_price_trr > 0),
 status public.terra_position_status not null default 'OPEN', opened_at timestamptz not null default now(), closed_at timestamptz, exit_trr_per_unit numeric(150,72), pnl_trr numeric(150,72), settled_equity_trr numeric(150,72)
);
create table public.terra_position_partitions (position_id uuid not null references public.terra_positions(id) on delete restrict, partition_id uuid not null references public.terra_partitions(id) on delete restrict, primary key(position_id,partition_id));

create table public.terra_pension_contracts (
 id uuid primary key default gen_random_uuid(), owner_user_id uuid not null references auth.users(id), term_years smallint not null check(term_years in (2,5,10)), contribution_percent smallint not null check(contribution_percent in (3,5,10)),
 annual_rate numeric(150,72) not null default .08 check(annual_rate >= 0), status public.terra_pension_status not null default 'ACTIVE', started_at date not null default current_date, matures_at date not null, closed_at timestamptz
);
create table public.terra_pension_contributions (
 id uuid primary key default gen_random_uuid(), contract_id uuid not null references public.terra_pension_contracts(id) on delete restrict, contribution_month date not null default current_date, contributed_at timestamptz not null default now(),
 monthly_earnings_trr numeric(150,72) not null check(monthly_earnings_trr >= 0), contribution_trr numeric(150,72) not null check(contribution_trr >= 0), immediate_payout_trr numeric(150,72) not null check(immediate_payout_trr >= 0), capitalized_trr numeric(150,72) not null check(capitalized_trr >= 0),
 check(contribution_trr = immediate_payout_trr + capitalized_trr), unique(contract_id, contribution_month)
);
-- RLS remains deny-by-default as in phase 1; private API role accesses this schema.
alter table public.terra_rbh_oracle enable row level security; alter table public.terra_asset_quotes enable row level security;
alter table public.terra_stakes enable row level security; alter table public.terra_stake_partitions enable row level security;
alter table public.terra_positions enable row level security; alter table public.terra_position_partitions enable row level security;
alter table public.terra_pension_contracts enable row level security; alter table public.terra_pension_contributions enable row level security;
revoke all on all tables in schema public from anon, authenticated;

-- Preserve zero-extract collateral: a partition committed to an open stake or open
-- synthetic position cannot be reassigned through the phase-1 ownership transfer RPC.
create or replace function public.terra_transfer_partitions(
  p_from uuid, p_to uuid, p_partition_ids uuid[], p_initiated_by uuid
) returns table(partition_id uuid, serial_number text, quantity numeric(150,72))
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid; v_row public.terra_partitions%rowtype;
begin
  if p_from = p_to then raise exception 'recipient must differ from current owner'; end if;
  if coalesce(array_length(p_partition_ids, 1), 0) = 0 then raise exception 'at least one partition is required'; end if;
  if exists (select 1 from unnest(p_partition_ids) x group by x having count(*) > 1) then raise exception 'duplicate partition'; end if;
  if not exists (select 1 from terra_identities where user_id=p_to and disabled_at is null) then raise exception 'recipient has no active TERRA identity'; end if;
  foreach v_id in array p_partition_ids loop
    select * into v_row from terra_partitions where id=v_id for update;
    if not found or v_row.retired_at is not null or v_row.owner_user_id <> p_from then raise exception 'partition % is unavailable or not owned by sender', v_id; end if;
    if exists (select 1 from terra_stake_partitions sp join terra_stakes s on s.id=sp.stake_id where sp.partition_id=v_id and s.claimed_at is null and s.cancelled_at is null)
       or exists (select 1 from terra_position_partitions pp join terra_positions x on x.id=pp.position_id where pp.partition_id=v_id and x.status='OPEN') then
      raise exception 'partition % is locked as collateral', v_id;
    end if;
    update terra_partitions set owner_user_id=p_to, transferred_at=now() where id=v_id;
    insert into terra_transfer_audit(from_user_id,to_user_id,partition_id,initiated_by) values (p_from,p_to,v_id,p_initiated_by);
    partition_id:=v_id; serial_number:=v_row.serial_number; quantity:=v_row.quantity; return next;
  end loop;
end $$;
