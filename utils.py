"""Here, the core of security and persistence for the passwords' manager."""

import os
import json
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Constants and paths.

DATA_DIR = "data"
PRIMARY_PASSWORD_FILE = os.path.join(DATA_DIR, "primary_password.json")
PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")
SALT = b"azertyuiop123456"


# Create the data directory if it doesn't exist.
def create_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


# Derivation of the Fernet key from the primary password.
def derive_fernet_key(primary_password: str) -> Fernet:

    """Here, transform the primary password (strings) in the key usable by Fernet for crypt/decrypt.
      For information, PBKDF2HMAC: algorithm for security key derivation. """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=SALT,
        iterations=100_000,
    )
    raw_key = kdf.derive(primary_password.encode()) # raw bytes
    b64_key = base64.urlsafe_b64encode(raw_key) # Base64 key
    return Fernet(b64_key)


# Storage initialization and reception of Fernet.
def init_storage() -> Fernet:

    """
    1. Create data directory
    2. Create or verify primary_password.json
    3. Return the Fernet key.
    """

    # If not primary the password exist, create it.
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        primary_password = input("Enter password for primary password: ")
        with open(PRIMARY_PASSWORD_FILE, "w") as f:
            json.dump({"primary_password": primary_password}, f)
        print("Primary password created and saved.")
        return derive_fernet_key(primary_password)
    # If primary the password exist, ask it and verify.
    else:
        with open(PRIMARY_PASSWORD_FILE, "r") as f:
            stored_primary_password = json.load(f).get("primary_password", "")
            attempt_primary_password = input("Enter the primary password: ").strip()
            if attempt_primary_password != stored_primary_password:
                raise SystemExit("Wrong primary password. The program will exit.")
    # Derivation of the key and push it again.
    return derive_fernet_key(attempt_primary_password)
