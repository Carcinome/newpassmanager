"""
Here, the core of security and persistence for the passwords' manager.
"""

import base64
import json
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

# Constants and paths.

DATA_DIR = "data"
PRIMARY_PASSWORD_FILE = os.path.join(DATA_DIR, "primary_password.json")
PASSWORDS_FILE = os.path.join(DATA_DIR, "passwords.json")
SALT_FILE = os.path.join(DATA_DIR, "salt.bin")


def get_or_create_salt():
    """
    Load the salt from the salt.bin file or create it if it doesn't exist.
    Salt ISN'T secret, just useful for making all derivations unic.
    """
    create_data_dir()
    if not os.path.exists(SALT_FILE):
        salt = os.urandom(16)  # 16 octets, 128 bits, enough.
        with open(SALT_FILE, "wb") as f:  # wb = write octets.
            f.write(salt)
        return salt
    with open(SALT_FILE, "rb") as f:  # rb = read octets.
        return f.read()


# Create the data directory if it doesn't exist.
def create_data_dir():
    os.makedirs(DATA_DIR, exist_ok=True)


# Derivation of the Fernet key from the primary password.
def derive_fernet_key(primary_password: str, salt: bytes, iterations: int = 200_000) -> Fernet:
    """
    Here, transform the primary password (strings) in the key usable by Fernet for crypt/decrypt.
    For information, PBKDF2HMAC: algorithm for security key derivation.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
    )
    raw_key = kdf.derive(primary_password.encode())  # raw bytes
    b64_key = base64.urlsafe_b64encode(raw_key)  # Base64 key
    return Fernet(b64_key)


def write_primary_verifier(primary_password: str, iterations: int = 200_000) -> None:
    """
    Write an JSON file "primary_password.json" without a password, with:
    - format version
    - KDF parameters
    - A verifier = secret crypted with the derived key.
    """
    create_data_dir()
    salt = get_or_create_salt()
    fernet = derive_fernet_key(primary_password, salt)
    secret = b"verify-v1"
    token = fernet.encrypt(secret).decode("utf-8")
    payload = {
        "version": 1,
        "kdf": {"name": "PBKDF2HMAC", "hash": "SHA256", "iterations": iterations},
        "verifier": token,
    }
    with open(PRIMARY_PASSWORD_FILE, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def verify_primary_password_and_get_key(entered_password: str) -> Fernet:
    """
    Read 'primary_password.json' and 'salt.bin',
    derive the key with 'entered_password' and try to decrypt the verifier.
    - If it works: return the Fernet object (correct key).
    - If it fails: raise InvalidToken.
    """
    if not os.path.exists(PRIMARY_PASSWORD_FILE):
        raise FileNotFoundError("No primary password found. Please create one first.")
    with open(PRIMARY_PASSWORD_FILE, encoding="utf-8") as f:
        data = json.load(f)

    # Old format (with 'primary_password' cleared) -> instant migration.
    if "primary_password" in data:
        stored = data.get("primary_password", "")
        if entered_password != stored:
            raise InvalidToken("Invalid primary password.")
        # Migration: write the new format and read again.
        write_primary_verifier(entered_password)
        with open(PRIMARY_PASSWORD_FILE, encoding="utf-8") as f2:
            data = json.load(f2)

    kdf = data.get("kdf", {})
    iterations = int(kdf.get("iterations", 200_000))
    verifier = data["verifier"]
    salt = get_or_create_salt()
    fernet = derive_fernet_key(entered_password, salt, iterations)

    try:
        _ = fernet.decrypt(verifier.encode("utf-8"))
    except InvalidToken:
        raise InvalidToken("Wrong primary password (cannot decrypt verifier).")
    return fernet


# Storage initialization and reception of Fernet.
def init_storage_primary_password() -> Fernet:
    """
    1. Create a data directory.
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
    # If the primary password exists, ask it and verify.
    else:
        with open(PRIMARY_PASSWORD_FILE) as f:
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
        with open(PASSWORDS_FILE) as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


# Write the passwords in the passwords.json file.
def save_passwords(passwords: dict):
    """
    Take the Python dictionary and save it in the passwords.json file.
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
    Decrypt the Base64 string "encrypting_token" and return the string cleared.
    If an error occurred, return InvalidToken.
    """
    # 1. For convert the token in octets.
    token_bytes = encrypted_token.encode()
    # 2. Let's decrypt.
    password_bytes = fernet.decrypt(token_bytes)
    # 3. Return the text version.
    return password_bytes.decode()
