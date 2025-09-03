"""
CRUD tests for the Vault model.
We assert the dictionary snapshot (to_dict_entry) for stability and clarity.
"""

import pytest

from src.vault.model import Entry


def test_add_single_entry(empty_vault):
    e = Entry(
        name="site", tags=["misc"], website="https://site.com", username="user", password="s3cr3t!"
    )
    empty_vault.add_vault_entry(e)

    assert "site" in empty_vault.iter_vault_entries()
    snap = empty_vault.to_dict_entry()
    assert snap["site"]["tags"] == ["misc"]
    assert snap["site"]["website"] == "https://site.com"
    assert snap["site"]["username"] == "user"
    assert snap["site"]["password"] == "s3cr3t!"


def test_add_duplicate_name_raises(empty_vault):
    e1 = Entry(name="duplicate_test", website="", username="", password="")
    e2 = Entry(name="duplicate_test", website="x", username="y", password="z")
    empty_vault.add_vault_entry(e1)
    with pytest.raises(ValueError):
        empty_vault.add_vault_entry(e2)


def test_update_overwrites_fields(vault_with_data):
    # Update the GitHub entry for test.
    vault_with_data.update_vault_entry(
        "Github",
        tags=["code", "work"],
        website="https://github.com",
        username="carci-update",
        password="GitP@ssw0rd",
    )
    snap = vault_with_data.to_dict_entry()
    assert snap["Github"]["tags"] == ["code", "work"]
    assert snap["Github"]["website"] == "https://github.com"
    assert snap["Github"]["username"] == "carci-update"
    assert snap["Github"]["password"] == "GitP@ssw0rd"


def test_delete_or_remove_entry(vault_with_data):
    assert "bank" in vault_with_data.iter_vault_entries()
    vault_with_data.delete_vault_entry("bank")
    assert "bank" not in vault_with_data.iter_vault_entries()


def test_rename_entry_by_delete_then_add(vault_with_data):
    # Simulate a rename operation.
    original = vault_with_data.iter_vault_entries()["gmail"]
    vault_with_data.delete_vault_entry("gmail")
    vault_with_data.add_vault_entry(
        Entry(
            name="gmail-work",
            tags=original.tags,
            website=original.website,
            username=original.username,
            password=original.password,
        )
    )
    assert "gmail" not in vault_with_data.iter_vault_entries()
    assert "gmail-work" in vault_with_data.iter_vault_entries()
