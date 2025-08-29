"""
Common pytest fixtures for the Password Manager project.
"""


import pytest

try:
    # Adjust these imports to the project layout if needed.
    from src.vault.model import Vault, Entry
except ModuleNotFoundError:
    raise

@pytest.fixture
def empty_vault():
    """
    Return a fresh vault with no entries.
    """
    return Vault()

@pytest.fixture
def sample_entries():
    """
    Provide 2-3 samples entries as plain dictionaries.
    """
    return [
        {"Name": "gmail", "Tags": ["work", "email"], "Website or application path": "https://mail.google.com", "Username": "carci", "Password": "Caa@rrrrrc1Gm@1L"},
        {"Name": "github", "Tags": ["work", "code", "personal"], "Website or application path": "https://www.github.com", "Username": "carci.git", "Password": "Caa@rrrrrc1g1t"},
        {"Name": "bank", "Tags": ["personal"], "Website or application path": "https://bank.com", "Username": "carci.bank", "Password": "Caa@rrrrrc1b@nK"}
    ]

@pytest.fixture
def vault_with_data(empty_vault, sample_entries):
    """
    Return a prefilled vault with a few entries.
    """
    for e in sample_entries:
        empty_vault.add_vault_entry(Entry(**e))
    return empty_vault

