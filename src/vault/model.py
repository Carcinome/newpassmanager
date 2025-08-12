
from future import annotations
from dataclasses import dataclass, field
from typing import Dict, Optional, List


"""
class Entry:
name: str
website: str = ""
username: str = ""
password: str = ""
tags: List[str] = field(default_factory=list)
"""

class Vault:
    """
    Represent all memories entries (not crypted when in RAM). It's a memory vault.
    No disk access here, no GUI, just rules and datas (CRUD).
    """
    def __init__(self) -> None:
        self._items: Dict[str, Entry] = {}


    def add_vault_entry(self, entry: Entry) -> None:
        if entry.name in self._items:
            raise ValueError(f"Entry {entry.name} already exists.")
        self._items[entry.name] = entry


    def get_vault_entry(self, name: str) -> Optional[Entry]:
        return self._items.get(name)0


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

