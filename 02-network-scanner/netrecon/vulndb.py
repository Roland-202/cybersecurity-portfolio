"""Local vulnerability knowledge base (JSON) and version matching."""
from __future__ import annotations

import json
from pathlib import Path

from .models import Severity
from .versions import is_affected

DEFAULT_DB = Path(__file__).parent / "data" / "vulndb.json"


def load_db(path: Path | str | None = None) -> list[dict]:
    entries = json.loads(Path(path or DEFAULT_DB).read_text(encoding="utf-8"))
    for e in entries:
        e["_severity"] = Severity.parse(e["severity"])
    return entries


def lookup(product: str, version: str, db: list[dict]) -> list[dict]:
    return [e for e in db if e["product"] == product and is_affected(version, e["affected"])]
