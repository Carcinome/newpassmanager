"""
Common pytest fixtures for the Password Manager project.
"""


import pytest

try:
    # Adjust these imports to the project layout if needed.
    from src.vault.model import Vault, Entry
except ModuleNotFoundError:
    raise


