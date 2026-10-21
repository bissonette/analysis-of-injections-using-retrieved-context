"""Журналирование решений фильтра и действий конвейера (JSONL)."""
from __future__ import annotations

import json
import time
from pathlib import Path


class AuditLog:
    def __init__(self, path: str | Path | None = None):
        self.path = Path(path) if path else None
        self.records: list[dict] = []

    def write(self, event: str, **data) -> None:
        rec = {"ts": time.time(), "event": event, **data}
        self.records.append(rec)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False, default=str) + "\n")
