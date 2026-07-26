#!/usr/bin/env python3
"""Print fresh environment values. Send these directly to a secret manager, not Git."""
import base64
import secrets
print("ADMIN_PASSWORD_SEED=" + base64.urlsafe_b64encode(secrets.token_bytes(48)).decode())
print("ADMIN_JWT_SECRET=" + base64.urlsafe_b64encode(secrets.token_bytes(48)).decode())
print("CERTIFICATE_SIGNING_KEY=" + base64.b64encode(secrets.token_bytes(32)).decode())
