"""Provider-neutral BaaS boundary. Partner secrets stay in environment/secret manager."""
import base64, hashlib, hmac, json
from cryptography.fernet import Fernet, InvalidToken
from fastapi import HTTPException

def verify_webhook(raw_body: bytes, provided_signature: str | None, secret: str) -> None:
    expected = hmac.new(secret.encode(), raw_body, hashlib.sha256).hexdigest()
    if not provided_signature or not hmac.compare_digest(provided_signature.removeprefix("sha256="), expected):
        raise HTTPException(401, "invalid partner webhook signature")

def event_payload(raw_body: bytes) -> dict:
    try:
        payload = json.loads(raw_body)
        if not isinstance(payload, dict) or not isinstance(payload.get("event_id"), str) or not isinstance(payload.get("type"), str): raise ValueError
        return payload
    except (ValueError, json.JSONDecodeError) as exc: raise HTTPException(422, "invalid partner event envelope") from exc

def encrypt_iban(iban: str, key: str) -> bytes:
    if len(iban) > 64 or not iban.replace(" ", "").isalnum(): raise ValueError("invalid account identifier")
    return Fernet(key.encode()).encrypt(iban.encode())
def decrypt_iban(ciphertext: bytes, key: str) -> str:
    try: return Fernet(key.encode()).decrypt(ciphertext).decode()
    except (InvalidToken, ValueError) as exc: raise HTTPException(500, "stored account data cannot be decrypted") from exc
