import base64

import pytest
from cryptography.exceptions import InvalidTag

from app.security import SecretBox, hash_password, token_hash, verify_password


def test_password_hash_is_argon2_and_verifies() -> None:
    encoded = hash_password("a long and unique password")
    assert encoded.startswith("$argon2id$")
    assert verify_password(encoded, "a long and unique password")
    assert not verify_password(encoded, "wrong password")


def test_token_hash_is_deterministic_without_storing_token() -> None:
    assert token_hash("secret") == token_hash("secret")
    assert token_hash("secret") != "secret"


def test_aes_gcm_round_trip_and_authentication() -> None:
    key = base64.urlsafe_b64encode(b"x" * 32).decode()
    box = SecretBox(key)
    ciphertext = box.encrypt("tskey-secret")
    assert b"tskey-secret" not in ciphertext
    assert box.decrypt(ciphertext) == "tskey-secret"
    with pytest.raises(InvalidTag):
        box.decrypt(ciphertext[:-1] + bytes([ciphertext[-1] ^ 1]))


def test_secret_box_rejects_wrong_key_length() -> None:
    with pytest.raises(ValueError):
        SecretBox(base64.urlsafe_b64encode(b"short").decode())
