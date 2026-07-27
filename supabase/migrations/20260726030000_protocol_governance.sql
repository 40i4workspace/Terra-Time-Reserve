-- Phase 4: auditable simulation protocol. NUMERIC(150,72) intentionally exceeds
-- NUMERIC(100,18): it safely holds both 10^72 and 72 fractional decimal places.
create type public.terra_cdco_direction as enum ('MINT','BURN');
create table public.terra_protocol_state (
 singleton boolean primary key default true check(singleton), total_supply_cap numeric(150,72) not null check(total_supply_cap = 1e72),
 circulating_supply numeric(150,72) not null default 0 check(circulating_supply >= 0 and circulating_supply <= total_supply_cap),
 target_rbh numeric(150,72) not null default 1 check(target_rbh > 0), updated_at timestamptz not null default now()
);
insert into public.terra_protocol_state(singleton,total_supply_cap,circulating_supply,target_rbh) values(true,1e72,0,1) on conflict(singleton) do nothing;
create table public.terra_cdco_cycles (
 id uuid primary key default gen_random_uuid(), cycle_id text not null unique check(length(cycle_id) between 8 and 120), observed_rbh numeric(150,72) not null check(observed_rbh > 0),
 target_rbh numeric(150,72) not null check(target_rbh > 0), deviation numeric(150,72) not null, direction public.terra_cdco_direction not null,
 amount numeric(150,72) not null check(amount > 0), entropy_commitment text not null, initiated_by text not null default 'ADMIN_ROOT', occurred_at timestamptz not null default now()
);
create type public.terra_split_currency as enum ('TRR','USD','EUR','GBP','USDT','PLN','JPY');
create table public.terra_smart_split_events (
 id uuid primary key default gen_random_uuid(), reference_type text not null check(length(reference_type) between 3 and 50), reference_id text not null check(length(reference_id) between 3 and 120),
 currency public.terra_split_currency not null, gross_amount numeric(150,72) not null check(gross_amount > 0), operations_amount numeric(150,72) not null check(operations_amount >= 0),
 gsc_amount numeric(150,72) not null check(gsc_amount >= 0), occurred_at timestamptz not null default now(), unique(reference_type,reference_id), check(gross_amount=operations_amount+gsc_amount)
);
create table public.terra_gsc_allocations (
 id uuid primary key default gen_random_uuid(), split_event_id uuid not null references public.terra_smart_split_events(id) on delete restrict,
 beneficiary_id text not null check(length(beneficiary_id) between 3 and 120), beneficiary_type text not null check(beneficiary_type in ('CHILDCARE','SHELTER','HOSPITAL')),
 amount numeric(150,72) not null check(amount > 0), allocation_status text not null default 'RESERVED' check(allocation_status in ('RESERVED','APPROVED','REPORTED')), created_at timestamptz not null default now()
);
alter table public.terra_protocol_state enable row level security; alter table public.terra_cdco_cycles enable row level security;
alter table public.terra_smart_split_events enable row level security; alter table public.terra_gsc_allocations enable row level security;
revoke all on public.terra_protocol_state,public.terra_cdco_cycles,public.terra_smart_split_events,public.terra_gsc_allocations from anon,authenticated;
