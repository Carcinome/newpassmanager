"""
Encrypted round-trip tests:
    - save_encrypted_vault(Vault, Fernet, path)
    - load_encrypted_vault(Fernet, path) -> Vault
For comparing snapshots to ensure exact persistence.
"""

import pytest
from cryptography.fernet import Fernet, InvalidToken

from src.vault.model import Entry, Vault
from src.vault.storage import load_encrypted_vault, save_encrypted_vault


def make_test_vault():
    v = Vault()
    v.add_vault_entry(
        Entry(
            name="gmail",
            tags=["email"],
            website="https://www.gmail.com",
            username="carci",
            password="gm@ilpassw0rd",
        )
    )
    v.add_vault_entry(
        Entry(
            name="Github",
            tags=["code"],
            website="https://www.github.com",
            username="carci",
            password="GitP@ssw0rd",
        )
    )
    return v


def test_roundtrip_with_random_key(tmp_path):
    # Fresh Fernet key used for the test (not modify or use KDF or salt).
    fernet = Fernet(Fernet.generate_key())

    original = make_test_vault()
    p = tmp_path / "vault_test.enc"

    # Save and load.
    save_encrypted_vault(original, fernet, str(p))
    assert p.exists() and p.stat().st_size > 0

    loaded = load_encrypted_vault(fernet, str(p))

    assert loaded.to_dict_entry() == original.to_dict_entry()


def test_wrong_key_cant_decrypt(tmp_path):
    p = tmp_path / "vault_test.enc"

    # Save with the key number 1.
    key_a = Fernet.generate_key()
    fernet_a = Fernet(key_a)
    save_encrypted_vault(make_test_vault(), fernet_a, str(p))

    # Try to load with the key number 2.
    key_b = Fernet.generate_key()
    fernet_b = Fernet(key_b)

    with pytest.raises((InvalidToken, Exception)):
        _ = load_encrypted_vault(fernet_b, str(p))
