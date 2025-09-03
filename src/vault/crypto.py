from __future__ import annotations

from cryptography.fernet import Fernet


# Here, we do not rebuild PBKDF2: we use the Fernet from utils.py.
# This file keeps an extension point if we want, later, use another mod.
def get_fernet_from_key(b64_key: bytes) -> Fernet:
    return Fernet(b64_key)
