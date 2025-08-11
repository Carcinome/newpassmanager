
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
    Represent all memories entries (not crypted when in RAM).
    No E/S here, no GUI, just rules and datas.
    """
    def __ini__(self) -> None:
        self._items: Dict[str, Entry] = {}
