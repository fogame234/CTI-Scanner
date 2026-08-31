"""
Encrypt/decrypt sensitive settings stored in the database.

Uses Fernet symmetric encryption. The encryption key is auto-generated
on first run and stored in a local file. If the key file is lost,
encrypted settings must be re-entered.
"""

import base64
import hashlib
import logging
import os
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

logger = logging.getLogger(__name__)

_KEY_FILE = Path(__file__).parent / ".secret_key"
_fernet: Fernet | None = None

# Settings keys that should be encrypted
SENSITIVE_KEYS = {"ntfy_token"}


def _get_fernet() -> Fernet:
    """Load or generate the encryption key."""
    global _fernet
    if _fernet is not None:
        return _fernet

    if _KEY_FILE.exists():
        key = _KEY_FILE.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        _KEY_FILE.write_bytes(key)
        # Restrict permissions on Unix
        try:
            os.chmod(_KEY_FILE, 0o600)
        except OSError:
            pass  # Windows
        logger.info("Generated new encryption key: %s", _KEY_FILE)

    _fernet = Fernet(key)
    return _fernet


def encrypt(value: str) -> str:
    """Encrypt a string. Returns a prefixed base64 string."""
    if not value:
        return ""
    f = _get_fernet()
    encrypted = f.encrypt(value.encode())
    return "enc:" + encrypted.decode()


def decrypt(value: str) -> str:
    """Decrypt a string. Returns plaintext. Handles unencrypted values gracefully."""
    if not value:
        return ""
    if not value.startswith("enc:"):
        return value  # not encrypted, return as-is (migration case)
    try:
        f = _get_fernet()
        decrypted = f.decrypt(value[4:].encode())
        return decrypted.decode()
    except InvalidToken:
        logger.warning("Failed to decrypt value (wrong key?)")
        return ""


def is_sensitive(key: str) -> bool:
    """Check if a settings key should be encrypted."""
    return key in SENSITIVE_KEYS
