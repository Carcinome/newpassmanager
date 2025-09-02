"""
Here, the gestion of the encrypted vault.
"""


from __future__ import annotations
import json
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken
from .model import Vault


def save_encrypted_vault(vault: Vault, fernet: Fernet, path: str) -> None:
    """
    Serialize the vault in JSON (bytes).
    Crypt the JSON with Fernet.
    Write a binary unic file.
    """
    plaintext = json.dumps(vault.to_dict_entry(), ensure_ascii=False).encode("utf-8")
    token = fernet.encrypt(plaintext)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(token)

def load_encrypted_vault(fernet: Fernet, path: str) -> Vault:
    """
    Read the binary file.
    Try to decrypt it.
    Parse the JSON file and rebuild a Vault.
    If the file doesn't exist: empty Vault.
    """
    p = Path(path)
    if not p.exists():
        return Vault()
    token = p.read_bytes()
    plaintext = fernet.decrypt(token)
    data = json.loads(plaintext.decode("utf-8"))
    return Vault.from_dict_entry(data)
