-- T.E.R.R.A. closed-vault ledger. Apply with the Supabase migration role, not the anon key.
create extension if not exists pgcrypto;

create type public.terra_denomination as enum ('TRR', 'HRR', 'DAY', 'MON');
create type public.certificate_status as enum ('ACTIVE', 'REVOKED', 'SUPERSEDED');

create table public.terra_denominations (
  code public.terra_denomination primary key,
  hours_per_unit numeric(150,72) not null check (hours_per_unit > 0),
  user_visible boolean not null default false,
  check ((code = 'HRR' and hours_per_unit = 1) or
         (code = 'TRR' and hours_per_unit = 1) or
         (code = 'DAY' and hours_per_unit = 24) or
         (code = 'MON' and hours_per_unit = 720))
);
insert into public.terra_denominations(code,hours_per_unit,user_visible) values
 ('HRR',1,true), ('TRR',1,true), ('DAY',24,false), ('MON',720,false);

-- auth.users holds login identity. biometric_binding_hash is an opaque verifier output,
-- never a raw biometric, template, image, or recoverable biometric identifier.
create table public.terra_identities (
  user_id uuid primary key references auth.users(id) on delete restrict,
  biometric_binding_hash bytea not null unique check (octet_length(biometric_binding_hash) = 32),
  created_at timestamptz not null default now(), disabled_at timestamptz
);

create table public.terra_partitions (
  id uuid primary key default gen_random_uuid(),
  serial_number text not null unique check (serial_number ~ '^TRR-[0-9]{4}-[0-9]{6}$'),
  denomination public.terra_denomination not null default 'TRR',
  quantity numeric(150,72) not null check (quantity > 0),
  -- This is an internal owner registry; it is deliberately not a wallet address.
  owner_user_id uuid not null references auth.users(id) on delete restrict,
  vault_location text not null default 'TERRA-MASTER-VAULT' check (vault_location = 'TERRA-MASTER-VAULT'),
  issued_at timestamptz not null default now(),
  transferred_at timestamptz,
  retired_at timestamptz
);
create index terra_partitions_owner_idx on public.terra_partitions(owner_user_id) where retired_at is null;

create table public.terra_certificates (
  id uuid primary key default gen_random_uuid(),
  certificate_number text not null unique default ('CERT-' || upper(encode(gen_random_bytes(12),'hex'))),
  owner_user_id uuid not null references auth.users(id) on delete restrict,
  recipient_key_fingerprint bytea not null check (octet_length(recipient_key_fingerprint) = 32),
  encrypted_envelope jsonb not null,
  issuer_signature bytea not null,
  status public.certificate_status not null default 'ACTIVE',
  issued_at timestamptz not null default now(), revoked_at timestamptz, revoked_reason text,
  check ((status = 'REVOKED') = (revoked_at is not null))
);
create index terra_certificates_owner_idx on public.terra_certificates(owner_user_id, status);
create table public.terra_certificate_partitions (
  certificate_id uuid not null references public.terra_certificates(id) on delete restrict,
  partition_id uuid not null references public.terra_partitions(id) on delete restrict,
  primary key(certificate_id, partition_id)
);

create table public.terra_transfer_audit (
  id uuid primary key default gen_random_uuid(),
  from_user_id uuid not null references auth.users(id), to_user_id uuid not null references auth.users(id),
  partition_id uuid not null references public.terra_partitions(id),
  initiated_by uuid references auth.users(id),
  occurred_at timestamptz not null default now(),
  reason text not null default 'ownership registry update'
);

-- No recipient wallet/external-address column exists by design.  The only mutation path
-- locks each partition, proves current ownership, and changes its internal registry entry.
create or replace function public.terra_transfer_partitions(
  p_from uuid, p_to uuid, p_partition_ids uuid[], p_initiated_by uuid
) returns table(partition_id uuid, serial_number text, quantity numeric(150,72))
language plpgsql security definer set search_path = public, pg_temp as $$
declare v_id uuid; v_row public.terra_partitions%rowtype;
begin
  if p_from = p_to then raise exception 'recipient must differ from current owner'; end if;
  if coalesce(array_length(p_partition_ids, 1), 0) = 0 then raise exception 'at least one partition is required'; end if;
  if exists (select 1 from unnest(p_partition_ids) x group by x having count(*) > 1) then raise exception 'duplicate partition'; end if;
  if not exists (select 1 from terra_identities where user_id = p_to and disabled_at is null) then
    raise exception 'recipient has no active TERRA identity';
  end if;
  foreach v_id in array p_partition_ids loop
    select * into v_row from terra_partitions where id = v_id for update;
    if not found or v_row.retired_at is not null or v_row.owner_user_id <> p_from then
      raise exception 'partition % is unavailable or not owned by sender', v_id;
    end if;
    update terra_partitions set owner_user_id=p_to, transferred_at=now() where id=v_id;
    insert into terra_transfer_audit(from_user_id,to_user_id,partition_id,initiated_by)
      values (p_from,p_to,v_id,p_initiated_by);
    partition_id := v_id; serial_number := v_row.serial_number; quantity := v_row.quantity; return next;
  end loop;
end $$;

create or replace function public.terra_revoke_certificate(p_certificate_id uuid, p_owner uuid, p_reason text)
returns void language plpgsql security definer set search_path = public, pg_temp as $$
begin
 update terra_certificates set status='REVOKED', revoked_at=now(), revoked_reason=left(p_reason, 500)
 where id=p_certificate_id and owner_user_id=p_owner and status='ACTIVE';
 if not found then raise exception 'active certificate not found for owner'; end if;
end $$;

-- Tables are private even to authenticated PostgREST clients. API backend uses a separate,
-- least-privilege database role that can execute only these functions and controlled inserts.
alter table public.terra_denominations enable row level security;
alter table public.terra_identities enable row level security;
alter table public.terra_partitions enable row level security;
alter table public.terra_certificates enable row level security;
alter table public.terra_certificate_partitions enable row level security;
alter table public.terra_transfer_audit enable row level security;

-- The migration owner must replace terra_vault_api with the actual non-superuser API role.
-- Do NOT grant INSERT/UPDATE/DELETE on terra_partitions to application roles.
revoke all on public.terra_denominations, public.terra_identities, public.terra_partitions,
  public.terra_certificates, public.terra_certificate_partitions, public.terra_transfer_audit from anon, authenticated;
revoke all on function public.terra_transfer_partitions(uuid,uuid,uuid[],uuid), public.terra_revoke_certificate(uuid,uuid,text) from public, anon, authenticated;

create sequence public.terra_partition_serial_seq start 1 minvalue 1 maxvalue 999999;
create or replace function public.terra_issue_partition(p_owner uuid, p_quantity numeric, p_denomination public.terra_denomination default 'TRR')
returns public.terra_partitions language plpgsql security definer set search_path = public, pg_temp as $$
declare v_partition public.terra_partitions%rowtype; v_sequence bigint;
begin
 if p_quantity is null or p_quantity <= 0 then raise exception 'quantity must be positive'; end if;
 if not exists (select 1 from terra_identities where user_id=p_owner and disabled_at is null) then raise exception 'owner has no active TERRA identity'; end if;
 v_sequence := nextval('public.terra_partition_serial_seq');
 insert into terra_partitions(serial_number, denomination, quantity, owner_user_id)
 values ('TRR-' || to_char(current_date, 'YYYY') || '-' || lpad(v_sequence::text, 6, '0'), p_denomination, p_quantity, p_owner)
 returning * into v_partition;
 return v_partition;
end $$;
revoke all on function public.terra_issue_partition(uuid,numeric,public.terra_denomination) from public, anon, authenticated;
