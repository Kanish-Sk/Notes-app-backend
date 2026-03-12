"""
Encryption helpers for sensitive values (Cloudinary credentials, etc.)
Replaces the encrypt/decrypt functions that were in user_database.py.
"""
import os
from cryptography.fernet import Fernet

_cipher: Fernet | None = None


def _get_cipher() -> Fernet:
    global _cipher
    if _cipher is None:
        key = os.getenv("DB_ENCRYPTION_KEY", "")
        if not key:
            raise ValueError("DB_ENCRYPTION_KEY is not set in environment")
        raw = key if isinstance(key, bytes) else key.encode()
        _cipher = Fernet(raw)
    return _cipher


def encrypt_value(value: str) -> str:
    """Encrypt a string value."""
    return _get_cipher().encrypt(value.encode()).decode()


def decrypt_value(encrypted: str) -> str:
    """Decrypt an encrypted string value."""
    return _get_cipher().decrypt(encrypted.encode()).decode()


# Aliases used across the codebase
encrypt_connection_string = encrypt_value
decrypt_connection_string = decrypt_value
