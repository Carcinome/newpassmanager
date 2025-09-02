"""
Common pytest fixtures for the Password Manager project.
"""


import pytest
import sys
from pathlib import Path

# Add the project root directory to the Python path.
PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

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
        {"name": "gmail", "tags": ["work", "email"], "website": "https://mail.google.com", "username": "carci", "password": "Caa@rrrrrc1Gm@1L"},
        {"name": "Github", "tags": ["work", "code", "personal"], "website": "https://www.github.com", "username": "carci.git", "password": "Caa@rrrrrc1g1t"},
        {"name": "bank", "tags": ["personal"], "website": "https://bank.com", "username": "carci.bank", "password": "Caa@rrrrrc1b@nK"}
    ]

@pytest.fixture
def vault_with_data(empty_vault, sample_entries):
    """s
    Return a prefilled vault with a few entries.
    """
    for e in sample_entries:
        empty_vault.add_vault_entry(Entry(**e))
    return empty_vault

