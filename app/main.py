import base64
import hashlib
import json
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Annotated, Literal
from uuid import UUID

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi import Depends, FastAPI, HTTPException, Request, status
from pydantic import BaseModel, Field, field_validator

from .db import VaultDatabase
from .money import AmountError, storage
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
