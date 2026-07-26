-- Phase 3: regulated partner boundary, optional fiat technical balances, and read-only education.
create type public.terra_currency as enum ('TRR','USD','EUR','GBP','USDT','PLN','JPY');
create type public.terra_partner_status as enum ('ACTIVE','SUSPENDED');

create table public.terra_baas_partners (
 id uuid primary key default gen_random_uuid(), slug text not null unique check(slug ~ '^[a-z0-9-]{3,48}$'), display_name text not null,
 status public.terra_partner_status not null default 'ACTIVE', created_at timestamptz not null default now()
);
create table public.terra_fiat_accounts (
 id uuid primary key default gen_random_uuid(), partner_id uuid not null references public.terra_baas_partners(id), owner_user_id uuid not null references auth.users(id),
 provider_account_ref text not null, iban_ciphertext bytea, currency public.terra_currency not null check(currency <> 'TRR'), status text not null check(status in ('PENDING','ACTIVE','SUSPENDED','CLOSED')),
 created_at timestamptz not null default now(), unique(partner_id,provider_account_ref)
);
create table public.terra_partner_events (
 partner_id uuid not null references public.terra_baas_partners(id), event_id text not null, received_at timestamptz not null default now(),
 event_type text not null, payload jsonb not null, processed_at timestamptz, primary key(partner_id,event_id)
);
create table public.terra_wallet_preferences (
 user_id uuid primary key references auth.users(id), multi_currency_enabled boolean not null default false,
 base_currency public.terra_currency not null default 'TRR', updated_at timestamptz not null default now()
);
create table public.terra_currency_ledger (
 id uuid primary key default gen_random_uuid(), owner_user_id uuid not null references auth.users(id), currency public.terra_currency not null,
 amount numeric(150,72) not null check(amount <> 0), reference_type text not null check(length(reference_type) <= 50), reference_id text not null check(length(reference_id) <= 120),
 occurred_at timestamptz not null default now(), unique(owner_user_id,currency,reference_type,reference_id)
);
create index terra_currency_ledger_balance_idx on public.terra_currency_ledger(owner_user_id,currency,occurred_at);
create table public.terra_fx_quotes (
 id uuid primary key default gen_random_uuid(), base_currency public.terra_currency not null, quote_currency public.terra_currency not null,
 rate numeric(150,72) not null check(rate > 0), source text not null, quoted_at timestamptz not null default now(), check(base_currency <> quote_currency)
);

create table public.terra_academy_patterns (
 slug text primary key check(slug ~ '^[a-z0-9-]{3,80}$'), title text not null, risk_level text not null check(risk_level in ('LOW','MEDIUM','HIGH')),
 summary text not null, lesson_markdown text not null, published boolean not null default true, updated_at timestamptz not null default now()
);
create type public.terra_academy_asset as enum ('GOLD','OIL','NATGAS','SILVER','BTC','USD','JPY','PLATINUM','ETH');
create table public.terra_historical_candles (
 asset public.terra_academy_asset not null, timeframe text not null check(timeframe in ('1D','1W')),
 opened_at timestamptz not null, open numeric(150,72) not null check(open > 0), high numeric(150,72) not null check(high > 0), low numeric(150,72) not null check(low > 0), close numeric(150,72) not null check(close > 0), volume numeric(150,72) check(volume >= 0), source text not null, primary key(asset,timeframe,opened_at), check(high >= low and high >= open and high >= close and low <= open and low <= close)
);

alter table public.terra_baas_partners enable row level security; alter table public.terra_fiat_accounts enable row level security;
alter table public.terra_partner_events enable row level security; alter table public.terra_wallet_preferences enable row level security;
alter table public.terra_currency_ledger enable row level security; alter table public.terra_fx_quotes enable row level security;
alter table public.terra_academy_patterns enable row level security; alter table public.terra_historical_candles enable row level security;
revoke all on all tables in schema public from anon, authenticated;

insert into public.terra_academy_patterns(slug,title,risk_level,summary,lesson_markdown) values
('support-resistance','Support and resistance','LOW','Areas where demand or supply has repeatedly reacted; treat them as zones, not exact lines.','Confirm with multiple touches, market context and invalidation. Do not size a position from a line alone.'),
('trend-continuation','Trend continuation','MEDIUM','Higher highs/higher lows or lower highs/lower lows can frame a trend.','Wait for a pullback and define risk before entry. A trend can end without warning; use a stop and modest exposure.'),
('double-top-bottom','Double top / double bottom','MEDIUM','A two-swing reversal structure whose neckline matters more than visual symmetry.','Require a close through the neckline and assess volume/liquidity. Avoid anticipating the break.'),
('head-and-shoulders','Head and shoulders','HIGH','A potential reversal with three pivots and a neckline.','It is probabilistic, not predictive. Set invalidation and avoid leverage when liquidity is thin.'),
('range-breakout','Range breakout','MEDIUM','Price exits a well-defined balance range.','False breakouts are common. Prefer confirmation, define the failed-breakout level, and keep risk per trade small.')
on conflict(slug) do update set title=excluded.title,risk_level=excluded.risk_level,summary=excluded.summary,lesson_markdown=excluded.lesson_markdown,updated_at=now();
