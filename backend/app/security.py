from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta

from argon2 import PasswordHasher
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .config import Settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(encoded: str, password: str) -> bool:
    try:
        return password_hasher.verify(encoded, password)
    except Exception:  # argon2 intentionally does not distinguish authentication errors
        return False


def new_token() -> str:
    return secrets.token_urlsafe(32)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def session_expiry(settings: Settings) -> datetime:
    return datetime.now(UTC) + timedelta(hours=settings.session_absolute_hours)


class SecretBox:
    def __init__(self, encoded_key: str) -> None:
        if not encoded_key:
            raise ValueError("TAILVIEW_ENCRYPTION_KEY is required")
        key = base64.urlsafe_b64decode(encoded_key)
        if len(key) != 32:
            raise ValueError("TAILVIEW_ENCRYPTION_KEY must decode to exactly 32 bytes")
        self._cipher = AESGCM(key)

    def encrypt(self, value: str) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + self._cipher.encrypt(nonce, value.encode(), b"tailview:v1")

    def decrypt(self, value: bytes) -> str:
        return self._cipher.decrypt(value[:12], value[12:], b"tailview:v1").decode()
