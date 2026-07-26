import base64
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import date, datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from .db import VaultDatabase
from .money import AmountError, storage, signed_storage
from .economics import (AssetCode, capital_value, pension_contribution, quote_in_time,
                        settle_leverage, stake_terms, leverage_terms)
from .security import (encrypt_certificate, issue_admin_token, require_admin, require_user,
                       verify_admin_password)
from .settings import Settings, get_settings

class AdminLogin(BaseModel):
    username: str
    password: str = Field(min_length=1, max_length=128)
class IdentityCreate(BaseModel):
    user_id: UUID
    biometric_binding_hash_b64: str
    @field_validator("biometric_binding_hash_b64")
    @classmethod
    def binding(cls, v):
        try: raw = base64.b64decode(v, validate=True)
        except Exception as exc: raise ValueError("must be base64") from exc
        if len(raw) != 32: raise ValueError("must encode exactly 32 bytes")
        return v
class MintRequest(BaseModel):
    owner_user_id: UUID
    quantity: str
    denomination: Literal["TRR", "HRR", "DAY", "MON"] = "TRR"
    recipient_x25519_public_key_pem: str
class TransferRequest(BaseModel):
    recipient_user_id: UUID
    partition_ids: list[UUID] = Field(min_length=1, max_length=500)
    recipient_x25519_public_key_pem: str
    @field_validator("partition_ids")
    @classmethod
    def unique(cls, v):
        if len(set(v)) != len(v): raise ValueError("partition IDs must be unique")
        return v
class RevokeRequest(BaseModel):
    reason: str = Field(min_length=3, max_length=500)

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings(); db = VaultDatabase(settings); db.open()
    app.state.db = db; app.state.settings = settings
    yield
    db.close()
app = FastAPI(title="T.E.R.R.A. Closed Vault API", version="1.0.0", lifespan=lifespan)

def db(request: Request) -> VaultDatabase: return request.app.state.db
def settings(request: Request) -> Settings: return request.app.state.settings

def _sign(payload: dict, settings: Settings) -> bytes:
    try: key = base64.b64decode(settings.certificate_signing_key.get_secret_value(), validate=True)
    except Exception as exc: raise RuntimeError("CERTIFICATE_SIGNING_KEY must be base64") from exc
    if len(key) != 32: raise RuntimeError("CERTIFICATE_SIGNING_KEY must be a 32-byte Ed25519 seed")
    return Ed25519PrivateKey.from_private_bytes(key).sign(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode())

def _certificate(conn, owner: UUID, partitions: list[dict], key_pem: str, settings: Settings) -> dict:
    issued_at = datetime.now(timezone.utc).isoformat()
    payload = {"version": 1, "issuer": settings.certificate_issuer, "owner_user_id": str(owner),
               "partitions": [{"serial_number": x["serial_number"], "quantity": storage(x["quantity"]), "denomination": x["denomination"]} for x in partitions],
               "issued_at": issued_at, "notice": "Registry ownership is authoritative; this certificate may be revoked."}
    signature = _sign(payload, settings)
    try: envelope = encrypt_certificate({**payload, "issuer_signature_b64": base64.b64encode(signature).decode()}, key_pem)
    except ValueError as exc: raise HTTPException(422, detail=str(exc)) from exc
    fingerprint = hashlib.sha256(key_pem.encode()).digest()
    row = conn.execute("""insert into terra_certificates(owner_user_id,recipient_key_fingerprint,encrypted_envelope,issuer_signature)
       values (%s,%s,%s::jsonb,%s) returning id,certificate_number,status,issued_at""",
       (owner, fingerprint, json.dumps(envelope), signature)).fetchone()
    conn.executemany("insert into terra_certificate_partitions(certificate_id,partition_id) values (%s,%s)",
                     [(row["id"], x["id"]) for x in partitions])
    return {**row, "envelope": envelope}

@app.get("/healthz")
def health(): return {"status": "ok", "model": "closed-vault"}

@app.post("/admin/login")
def admin_login(body: AdminLogin, s: Annotated[Settings, Depends(settings)]):
    if body.username != s.admin_username or not verify_admin_password(body.password, s):
        raise HTTPException(status_code=401, detail="invalid credentials")
    return {"access_token": issue_admin_token(s), "token_type": "bearer", "role": "ADMIN_ROOT"}

@app.post("/admin/identities", status_code=201)
def create_identity(body: IdentityCreate, request: Request, _: dict = Depends(require_admin)):
    raw = base64.b64decode(body.biometric_binding_hash_b64)
    try:
        with db(request).transaction() as conn:
            conn.execute("insert into terra_identities(user_id,biometric_binding_hash) values (%s,%s)", (body.user_id, raw))
    except Exception as exc: raise HTTPException(409, detail="identity cannot be registered") from exc
    return {"user_id": body.user_id, "registered": True}

@app.get("/admin/denominations")
def admin_denominations(request: Request, _: dict = Depends(require_admin)):
    """Administrative inventory includes intentionally hidden DAY and MON units."""
    with db(request).pool.connection() as conn:
        rows = conn.execute("select code,hours_per_unit,user_visible from terra_denominations order by code").fetchall()
    return [{**row, "hours_per_unit": storage(row["hours_per_unit"])} for row in rows]

@app.get("/admin/partitions")
def admin_partitions(request: Request, _: dict = Depends(require_admin)):
    with db(request).pool.connection() as conn:
        rows = conn.execute("""select id,serial_number,denomination,quantity,owner_user_id,vault_location,issued_at,transferred_at
            from terra_partitions where retired_at is null order by serial_number""").fetchall()
    return [{**row, "quantity": storage(row["quantity"])} for row in rows]

@app.post("/admin/partitions", status_code=201)
def mint_partition(body: MintRequest, request: Request, s: Annotated[Settings, Depends(settings)], _: dict = Depends(require_admin)):
    try: quantity = storage(body.quantity)
    except AmountError as exc: raise HTTPException(422, detail=str(exc)) from exc
    try:
        with db(request).transaction() as conn:
            partition = conn.execute("select * from terra_issue_partition(%s,%s::numeric,%s::terra_denomination)",
               (body.owner_user_id, quantity, body.denomination)).fetchone()
            certificate = _certificate(conn, body.owner_user_id, [partition], body.recipient_x25519_public_key_pem, s)
    except HTTPException: raise
    except Exception as exc: raise HTTPException(409, detail="partition issuance failed") from exc
    return {"partition": {"id": partition["id"], "serial_number": partition["serial_number"], "quantity": storage(partition["quantity"]), "vault_location": "TERRA-MASTER-VAULT"}, "certificate": certificate}

@app.get("/me/partitions")
def my_partitions(request: Request, user: UUID = Depends(require_user)):
    # Hidden higher-order units are intentionally omitted from normal user UI/API.
    rows = [r for r in db(request).user_partitions(user) if r["denomination"] in ("TRR", "HRR")]
    return [{**r, "quantity": storage(r["quantity"])} for r in rows]

@app.post("/me/transfers", status_code=201)
def transfer(body: TransferRequest, request: Request, user: UUID = Depends(require_user), s: Annotated[Settings, Depends(settings)] = None):
    try:
        with db(request).transaction() as conn:
            rows = conn.execute("select * from terra_transfer_partitions(%s,%s,%s,%s)",
              (user, body.recipient_user_id, body.partition_ids, user)).fetchall()
            conn.execute("""update terra_certificates set status='SUPERSEDED'
              where owner_user_id=%s and status='ACTIVE' and id in
              (select certificate_id from terra_certificate_partitions where partition_id = any(%s))""", (user, body.partition_ids))
            certificate = _certificate(conn, body.recipient_user_id, rows, body.recipient_x25519_public_key_pem, s)
    except HTTPException: raise
    except Exception as exc: raise HTTPException(409, detail="transfer rejected by vault registry") from exc
    return {"transferred": [{"serial_number": r["serial_number"], "quantity": storage(r["quantity"])} for r in rows], "certificate": certificate}

@app.post("/me/certificates/{certificate_id}/revoke")
def revoke(certificate_id: UUID, body: RevokeRequest, request: Request, user: UUID = Depends(require_user)):
    try:
        with db(request).transaction() as conn:
            conn.execute("select terra_revoke_certificate(%s,%s,%s)", (certificate_id, user, body.reason))
    except Exception as exc: raise HTTPException(404, detail="active certificate not found") from exc
    return {"certificate_id": certificate_id, "status": "REVOKED", "vault_tokens_remain_locked": True}


# ---- Time-denominated economics -------------------------------------------------
class OracleQuoteRequest(BaseModel):
    observed_rbh_usd: str
    baseline_rbh_usd: str = "30"
    source: str = Field(min_length=3, max_length=120)
    asset_prices_usd: dict[AssetCode, str] = Field(min_length=1)
class StakeRequest(BaseModel):
    partition_ids: list[UUID] = Field(min_length=1, max_length=500)
    term_days: Literal[30, 90, 180, 365]
class PositionRequest(BaseModel):
    asset: AssetCode
    side: Literal["LONG", "SHORT"]
    leverage: Literal[1, 2, 5, 10, 20]
    collateral_partition_ids: list[UUID] = Field(min_length=1, max_length=500)
class ClosePositionRequest(BaseModel):
    exit_trr_per_unit: str
class PensionContractRequest(BaseModel):
    term_years: Literal[2, 5, 10]
    contribution_percent: Literal[3, 5, 10]
class PensionContributionRequest(BaseModel):
    monthly_earnings_trr: str
    contribution_month: date

def _locked_collateral(conn, owner: UUID, partition_ids: list[UUID]) -> list[dict]:
    """Lock collateral and prove it is not already committed to an open stake/position."""
    if len(set(partition_ids)) != len(partition_ids):
        raise ValueError("duplicate partition IDs")
    rows = conn.execute("""select p.* from terra_partitions p
      where p.id = any(%s) and p.owner_user_id=%s and p.retired_at is null for update""", (partition_ids, owner)).fetchall()
    if len(rows) != len(partition_ids): raise ValueError("all collateral must be active partitions owned by caller")
    busy = conn.execute("""select partition_id from terra_stake_partitions sp join terra_stakes s on s.id=sp.stake_id
      where sp.partition_id=any(%s) and s.claimed_at is null and s.cancelled_at is null
      union select partition_id from terra_position_partitions pp join terra_positions x on x.id=pp.position_id
      where pp.partition_id=any(%s) and x.status='OPEN'""", (partition_ids, partition_ids)).fetchall()
    if busy: raise ValueError("one or more partitions are locked as collateral")
    return rows

def _total(rows: list[dict]):
    from decimal import Decimal
    return sum((r["quantity"] for r in rows), Decimal("0"))

@app.post("/admin/economy/quotes", status_code=201)
def publish_time_quotes(body: OracleQuoteRequest, request: Request, _: dict = Depends(require_admin)):
    """Publish auditable source quotes; supplied USD values are converted to guarded RBH/TRR values."""
    try:
        quotes = [quote_in_time(asset, value, body.observed_rbh_usd, body.baseline_rbh_usd)
                  for asset, value in body.asset_prices_usd.items()]
        with db(request).transaction() as conn:
            oracle = conn.execute("""insert into terra_rbh_oracle(observed_rbh_usd,baseline_rbh_usd,source,submitted_by)
              values(%s,%s,%s,'ADMIN_ROOT') returning id""", (storage(body.observed_rbh_usd), storage(body.baseline_rbh_usd), body.source)).fetchone()
            conn.executemany("""insert into terra_asset_quotes(asset,source_price_usd,rbh_oracle_id,trr_per_unit,source)
              values(%s,%s,%s,%s,%s)""", [(q.asset.value, storage(q.source_price_usd), oracle["id"], storage(q.trr_per_unit), body.source) for q in quotes])
    except (ValueError, AmountError) as exc: raise HTTPException(422, detail=str(exc)) from exc
    return [{"asset": q.asset, "source_price_usd": storage(q.source_price_usd), "effective_rbh_usd": storage(q.effective_rbh_usd),
             "peg_lower_usd": storage(q.peg_lower_usd), "peg_upper_usd": storage(q.peg_upper_usd), "trr_per_unit": storage(q.trr_per_unit)} for q in quotes]

@app.get("/economy/quotes")
def latest_time_quotes(request: Request):
    with db(request).pool.connection() as conn:
        rows = conn.execute("""select distinct on (asset) asset,source_price_usd,trr_per_unit,source,quoted_at
          from terra_asset_quotes order by asset,quoted_at desc""").fetchall()
    return [{**r, "source_price_usd": storage(r["source_price_usd"]), "trr_per_unit": storage(r["trr_per_unit"])} for r in rows]

@app.post("/me/stakes", status_code=201)
def create_stake(body: StakeRequest, request: Request, user: UUID = Depends(require_user)):
    try:
        with db(request).transaction() as conn:
            collateral = _locked_collateral(conn, user, body.partition_ids)
            terms = stake_terms(body.term_days, _total(collateral))
            row = conn.execute("""insert into terra_stakes(owner_user_id,principal_trr,term_days,power_multiplier,reward_trr,matures_at)
              values(%s,%s,%s,%s,%s,%s) returning id,started_at,matures_at""", (user, storage(terms["principal_trr"]), body.term_days, terms["power_multiplier"], storage(terms["reward_trr"]), terms["maturity_date"])).fetchone()
            conn.executemany("insert into terra_stake_partitions(stake_id,partition_id) values(%s,%s)", [(row["id"], x) for x in body.partition_ids])
    except ValueError as exc: raise HTTPException(409, detail=str(exc)) from exc
    return {**row, "principal_trr": storage(terms["principal_trr"]), "power_multiplier": str(terms["power_multiplier"]), "reward_trr": storage(terms["reward_trr"])}

@app.post("/me/positions", status_code=201)
def open_position(body: PositionRequest, request: Request, user: UUID = Depends(require_user)):
    try:
        with db(request).transaction() as conn:
            collateral = _locked_collateral(conn, user, body.collateral_partition_ids)
            quote = conn.execute("select trr_per_unit from terra_asset_quotes where asset=%s order by quoted_at desc limit 1", (body.asset.value,)).fetchone()
            if not quote: raise ValueError("no current time quote for asset")
            terms = leverage_terms(_total(collateral), body.leverage, quote["trr_per_unit"], body.side)
            row = conn.execute("""insert into terra_positions(owner_user_id,asset,side,leverage,margin_trr,notional_trr,entry_trr_per_unit,units,liquidation_price_trr)
              values(%s,%s,%s,%s,%s,%s,%s,%s,%s) returning id,opened_at""", (user, body.asset.value, body.side, body.leverage, storage(terms["margin_trr"]), storage(terms["notional_trr"]), storage(quote["trr_per_unit"]), storage(terms["units"]), storage(terms["liquidation_price_trr"]))).fetchone()
            conn.executemany("insert into terra_position_partitions(position_id,partition_id) values(%s,%s)", [(row["id"], x) for x in body.collateral_partition_ids])
    except ValueError as exc: raise HTTPException(409, detail=str(exc)) from exc
    return {**row, **{k: storage(v) if hasattr(v, "as_tuple") else v for k,v in terms.items()}}

@app.post("/me/positions/{position_id}/close")
def close_position(position_id: UUID, body: ClosePositionRequest, request: Request, user: UUID = Depends(require_user)):
    try:
        with db(request).transaction() as conn:
            row = conn.execute("select * from terra_positions where id=%s and owner_user_id=%s and status='OPEN' for update", (position_id,user)).fetchone()
            if not row: raise ValueError("open position not found")
            settled = settle_leverage(row["margin_trr"], row["leverage"], row["entry_trr_per_unit"], body.exit_trr_per_unit, row["side"])
            state = "LIQUIDATED" if settled["liquidated"] else "CLOSED"
            conn.execute("update terra_positions set status=%s,closed_at=now(),exit_trr_per_unit=%s,pnl_trr=%s,settled_equity_trr=%s where id=%s", (state, storage(settled["exit_trr_per_unit"]), signed_storage(settled["pnl_trr"]), storage(settled["settled_equity_trr"]), position_id))
    except (ValueError, AmountError) as exc: raise HTTPException(409, detail=str(exc)) from exc
    return {"position_id": position_id, "status": state, "pnl_trr": signed_storage(settled["pnl_trr"]), "settled_equity_trr": storage(settled["settled_equity_trr"]), "internal_settlement_only": True}

@app.post("/me/pension-contracts", status_code=201)
def create_pension_contract(body: PensionContractRequest, request: Request, user: UUID = Depends(require_user)):
    from datetime import timedelta
    today = date.today()
    with db(request).transaction() as conn:
        row = conn.execute("""insert into terra_pension_contracts(owner_user_id,term_years,contribution_percent,matures_at)
          values(%s,%s,%s,%s) returning id,started_at,matures_at,status,annual_rate""", (user,body.term_years,body.contribution_percent,today + timedelta(days=365 * body.term_years))).fetchone()
    return {**row, "annual_rate": storage(row["annual_rate"])}

@app.post("/me/pension-contracts/{contract_id}/contributions", status_code=201)
def fund_pension(contract_id: UUID, body: PensionContributionRequest, request: Request, user: UUID = Depends(require_user)):
    try:
        with db(request).transaction() as conn:
            contract = conn.execute("select * from terra_pension_contracts where id=%s and owner_user_id=%s and status='ACTIVE' for update", (contract_id,user)).fetchone()
            if not contract: raise ValueError("active pension contract not found")
            terms = pension_contribution(body.monthly_earnings_trr, contract["contribution_percent"])
            row = conn.execute("""insert into terra_pension_contributions(contract_id,contribution_month,monthly_earnings_trr,contribution_trr,immediate_payout_trr,capitalized_trr)
              values(%s,%s,%s,%s,%s,%s) returning id,contributed_at""", (contract_id,body.contribution_month,storage(terms["monthly_earnings_trr"]),storage(terms["contribution_trr"]),storage(terms["immediate_payout_trr"]),storage(terms["capitalized_trr"]))).fetchone()
    except (ValueError, AmountError) as exc: raise HTTPException(409, detail=str(exc)) from exc
    return {**row, **{k: storage(v) for k,v in terms.items()}, "immediate_payout_status": "internal payout entitlement"}

@app.post("/me/pension-contracts/{contract_id}/close")
def close_pension_contract(contract_id: UUID, request: Request, user: UUID = Depends(require_user)):
    """Close without a penalty; paid 10% instalments remain paid and all remaining principal is returned internally."""
    try:
        with db(request).transaction() as conn:
            contract = conn.execute("select * from terra_pension_contracts where id=%s and owner_user_id=%s and status='ACTIVE' for update", (contract_id,user)).fetchone()
            if not contract: raise ValueError("active pension contract not found")
            capital = conn.execute("select coalesce(sum(capitalized_trr),0) as capital from terra_pension_contributions where contract_id=%s", (contract_id,)).fetchone()["capital"]
            payouts = conn.execute("select coalesce(sum(immediate_payout_trr),0) as payouts from terra_pension_contributions where contract_id=%s", (contract_id,)).fetchone()["payouts"]
            conn.execute("update terra_pension_contracts set status='CLOSED',closed_at=now() where id=%s", (contract_id,))
    except ValueError as exc: raise HTTPException(404, detail=str(exc)) from exc
    return {"contract_id": contract_id, "status": "CLOSED", "penalty_trr": storage("0"), "returned_remaining_principal_trr": storage(capital), "already_paid_trr": storage(payouts), "settlement": "internal vault entitlement"}

@app.get("/me/pension-contracts/{contract_id}")
def pension_projection(contract_id: UUID, request: Request, user: UUID = Depends(require_user)):
    with db(request).pool.connection() as conn:
        contract = conn.execute("select * from terra_pension_contracts where id=%s and owner_user_id=%s", (contract_id,user)).fetchone()
        if not contract: raise HTTPException(404, detail="pension contract not found")
        rows = conn.execute("select * from terra_pension_contributions where contract_id=%s", (contract_id,)).fetchall()
    total = sum((capital_value(r["capitalized_trr"], max(0, (contract["matures_at"].year-r["contribution_month"].year)*12 + contract["matures_at"].month-r["contribution_month"].month), contract["annual_rate"]) for r in rows), __import__('decimal').Decimal("0"))
    return {"contract_id": contract_id, "status": contract["status"], "matures_at": contract["matures_at"], "contribution_count": len(rows), "projected_capital_trr": storage(total), "early_close_return_trr": storage(sum((r["capitalized_trr"] for r in rows), __import__('decimal').Decimal("0"))), "note": "Projection is mathematical, not a guaranteed return; settlement remains inside the vault."}
