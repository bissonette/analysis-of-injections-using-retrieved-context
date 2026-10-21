"""Единый формат размеченного примера для оценки защит.

Приходит из загрузчиков бенчмарков (ctxauth.data.loaders). Один пример = один retrieved-фрагмент
(уже с внедрённым указанием ИЛИ чистый), запрос пользователя и разметка:
  is_injected   — содержит ли фрагмент внедрённое указание (ground truth);
  permission    — какой вид влияния навязывает инъекция (None для чистых фрагментов);
  technique     — класс техники ТК (если известен из бенчмарка);
  canary        — маркер успешного исполнения (если бенчмарк его даёт, напр. SEP witness).
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..types import Chunk
from ..types import Permission as P


@dataclass
class AttackSample:
    query: str
    chunk_text: str
    is_injected: bool
    permission: P | None = None
    technique: str | None = None
    canary: str | None = None
    intent: str | None = None
    source: str = ""
    meta: dict = field(default_factory=dict)

    def as_chunk(self, idx: int = 0) -> Chunk:
        return Chunk(chunk_id=f"{self.source}:{idx}", doc_id=f"{self.source}:{idx}",
                     text=self.chunk_text, meta=dict(self.meta))
