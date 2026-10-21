"""Ретривер: поиск top-k фрагментов + опциональный лексический реранкер."""
from __future__ import annotations

from dataclasses import replace

from ..text import words
from ..types import Chunk
from .index import VectorIndex


class Retriever:
    def __init__(self, index: VectorIndex, k: int = 5, rerank: bool = False, candidates: int = 20):
        self.index, self.k, self.rerank, self.candidates = index, k, rerank, candidates

    def retrieve(self, query: str) -> list[Chunk]:
        hits = self.index.search(query, self.candidates if self.rerank else self.k)
        if self.rerank:
            q = set(words(query))
            hits.sort(key=lambda h: -(h[1] + 0.05 * len(q & set(words(h[0].text)))))
            hits = hits[: self.k]
        return [replace(c, score=s) for c, s in hits]
