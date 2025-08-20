
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional, List


@dataclass
class Entry:
    name: str
    website: str = ""
    username: str = ""
    password: str = ""
    tags: List[str] = field(default_factory=list)


class Vault:
    """
    Represent all memory entries (not crypted when in RAM). It's a memory vault.
    No disk access here, no GUI, just rules and datas (CRUD).
    """
    def __init__(self) -> None:
        self._items: Dict[str, Entry] = {}

    def add_vault_entry(self, entry: Entry) -> None:
        if entry.name in self._items:
            raise ValueError(f"Entry {entry.name} already exists.")
        self._items[entry.name] = entry

    def get_vault_entry(self, name: str) -> Optional[Entry]:
        return self._items.get(name)

    def update_vault_entry(self, name: str, **fields) -> None:
        if name not in self._items:
            raise KeyError(f"Entry {name} not found.")
        e = self._items[name]
        for k, v in fields.items():
            if hasattr(e, k):
                setattr(e, k, v)

    def delete_vault_entry(self, name: str) -> None:
        if name not in self._items:
            raise KeyError(f"Entry {name} not found.")
        del self._items[name]

    def to_dict_entry(self) -> Dict[str, dict]:
        return {
            name: {
                "website": e.website,
                "username": e.username,
                "password": e.password,
                "tags": list(e.tags),
            }
            for name, e in self._items.items()
        }

    @classmethod
    def from_dict_entry(cls, data: Dict[str, dict]) -> "Vault":
        vault = cls()
        for name, d in data.items():
            vault.add_vault_entry(Entry(
                name=name,
                website=d.get("website", ""),
                username=d.get("username", ""),
                password=d.get("password", ""),
                tags=d.get("tags", []),
            ))
        return vault


