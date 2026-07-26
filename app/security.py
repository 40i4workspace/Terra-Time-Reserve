"""Authentication and certificate cryptography.

No biometric template is accepted or stored.  A client/identity provider derives a
biometric binding hash; TERRA only stores that opaque, salted binding identifier.
"""
import base64
import hashlib
import hmac
import json
import time
from datetime import datetime, timedelta, timezone
from uuid import UUID

import jwt
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from .settings import Settings, get_settings

bearer = HTTPBearer(auto_error=True)

def _admin_code(seed: bytes, period: int, digits: int, slot: int) -> str:
    digest = hmac.new(seed, f"TERRA/ADMIN_ROOT/{slot}".encode(), hashlib.sha512).digest()
    return str(int.from_bytes(digest[:16], "big") % (10**digits)).zfill(digits)

def current_admin_password(settings: Settings, now: int | None = None) -> str:
    """Derive a rotating one-time ADMIN_ROOT password; never persist it."""
    stamp = int(time.time() if now is None else now)
    return _admin_code(settings.admin_password_seed.get_secret_value().encode(),
                       settings.admin_password_period_seconds, settings.admin_password_digits,
                       stamp // settings.admin_password_period_seconds)

def verify_admin_password(password: str, settings: Settings) -> bool:
    now_slot = int(time.time()) // settings.admin_password_period_seconds
    seed = settings.admin_password_seed.get_secret_value().encode()
    # Grace window only for a request crossing a rotation boundary.
    return any(hmac.compare_digest(password, _admin_code(seed, settings.admin_password_period_seconds,
                                                          settings.admin_password_digits, slot))
               for slot in (now_slot, now_slot - 1))

def issue_admin_token(settings: Settings) -> str:
    now = datetime.now(timezone.utc)
    return jwt.encode({"sub": "ADMIN_ROOT", "role": "ADMIN_ROOT", "iss": "terra-vault",
                       "iat": now, "exp": now + timedelta(minutes=10)},
                      settings.admin_jwt_secret.get_secret_value(), algorithm="HS512")

def require_admin(credentials: HTTPAuthorizationCredentials = Depends(bearer),
                  settings: Settings = Depends(get_settings)) -> dict:
    try:
        claims = jwt.decode(credentials.credentials, settings.admin_jwt_secret.get_secret_value(),
                            algorithms=["HS512"], issuer="terra-vault")
    except jwt.PyJWTError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid admin token") from exc
    if claims.get("sub") != "ADMIN_ROOT" or claims.get("role") != "ADMIN_ROOT":
        raise HTTPException(status_code=403, detail="ADMIN_ROOT required")
    return claims

def require_user(credentials: HTTPAuthorizationCredentials = Depends(bearer),
                 settings: Settings = Depends(get_settings)) -> UUID:
    """Verify a Supabase access token locally and return its immutable auth.uid()."""
    try:
        claims = jwt.decode(credentials.credentials, settings.supabase_jwt_secret.get_secret_value(),
                            algorithms=["HS256"], audience="authenticated",
                            issuer=f"{settings.supabase_url}/auth/v1")
        return UUID(claims["sub"])
    except (jwt.PyJWTError, KeyError, ValueError) as exc:
        raise HTTPException(status_code=401, detail="invalid user token") from exc

def encrypt_certificate(payload: dict, recipient_x25519_public_key_pem: str) -> dict[str, str]:
    """Seal a JSON certificate to a recipient's X25519 key (ephemeral ECDH + AES-256-GCM)."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    try:
        recipient = serialization.load_pem_public_key(recipient_x25519_public_key_pem.encode())
        if not isinstance(recipient, X25519PublicKey):
            raise TypeError("not X25519")
    except Exception as exc:
        raise ValueError("certificate key must be an X25519 PEM public key") from exc
    ephemeral = X25519PrivateKey.generate()
    nonce = __import__("os").urandom(12)
    shared = ephemeral.exchange(recipient)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
               info=b"TERRA-VAULT certificate v1").derive(shared)
    ciphertext = AESGCM(key).encrypt(nonce, json.dumps(payload, separators=(",", ":"), sort_keys=True).encode(), None)
    public = ephemeral.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"algorithm": "X25519-HKDF-SHA256-AES-256-GCM",
            "ephemeral_public_key_b64": base64.b64encode(public).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(), "ciphertext_b64": base64.b64encode(ciphertext).decode()}
