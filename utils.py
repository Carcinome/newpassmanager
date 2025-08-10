"""Here, the core of security and persistence for the passwords' manager."""

import os
import json
import base64
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# Constants and paths.

DATA_DIR                = "data"
PRIMARY_PASSWORD_FILE   = os.path.join(DATA_DIR, "primary_password.json")
PASSWORDS_FILE          = os.path.join(DATA_DIR, "passwords.json")
SALT_FILE               = os.path.join(DATA_DIR, "salt.bin")


def get_or_create_salt():
    """
    Load the salt from the salt.bin file, or create it if it doesn't exist.
    Salt ISN'T secret, just useful for make all derivations unic.
    """
    create_data_dir()
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16) # 16 octets, 128 bits, enough.
        with open(SALT_FILE, "wb") as f:
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:
        return f.read()


# Create the data directory if it doesn't exist.
def create_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


# Derivation of the Fernet key from the primary password.
def derive_fernet_key(primary_password: str, salt: bytes) -> Fernet:
    """
    Here, transform the primary password (strings) in the key usable by Fernet for crypt/decrypt.
    For information, PBKDF2HMAC: algorithm for security key derivation.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    raw_key = kdf.derive(primary_password.encode()) # raw bytes
    b64_key = base64.urlsafe_b64encode(raw_key) # Base64 key
    return Fernet(b64_key)


# Storage initialization and reception of Fernet.
def init_storage_primary_password() -> Fernet:
    """
    1. Create data directory.
    2. Create or verify primary_password.json.
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


# Load and read the passwords.
def load_passwords() -> dict:
    """
    Read passwords.json and returns a Python dictionary.
    If the file doesn't exist, or it is empty, return an empty dictionary.
    """
    create_data_dir()
    if not os.path.exists(PASSWORDS_FILE):
        return {}
    try:
        with open(PASSWORDS_FILE, "r") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


# Write the passwords in passwords.json file.
def save_passwords(passwords: dict):
    """
    Take the Python dictionary and save it in passwords.json file.
    """
    create_data_dir()
    with open(PASSWORDS_FILE, "w") as f:
        json.dump(passwords, f, indent=4)


def encrypt_password(fernet, password: str) -> str:
    """
    Crypt the "password" string with object Fernet and return the string encoded in Base64.
    """
    # 1. For convert the string in octets.
    password_bytes = password.encode()
    # 2. Crypt the octets.
    encrypted_token = fernet.encrypt(password_bytes)
    # 3. Return the text version.
    return encrypted_token.decode()


def decrypt_password(fernet, encrypted_token: str) -> str:
    """
    Decrypt the Base64 string "encrypting_token" and return the string cleared. If error occurred, return InvalidToken.
    """
    # 1. For convert the token in octets.
    token_bytes = encrypted_token.encode()
    # 2. Let's decrypt.
    password_bytes = fernet.decrypt(token_bytes)
    # 3. Return the text version.
    return password_bytes.decode()


