"""Векторное хранилище фрагментов (in-memory, косинусная близость)."""
from __future__ import annotations

import numpy as np
import scipy.sparse as sp

from ..types import Chunk


class VectorIndex:
    def __init__(self, embedder):
        self.embedder = embedder
        self.chunks: list[Chunk] = []
        self.matrix = None

    def build(self, chunks: list[Chunk]) -> "VectorIndex":
        self.chunks = list(chunks)
        texts = [c.text for c in self.chunks]
        self.embedder.fit(texts)
        self.matrix = self.embedder.encode(texts)
        return self

    def add(self, chunks: list[Chunk]) -> None:
        """Добавление без переобучения эмбеддера (канал индексации нарушителя, И-2)."""
        m = self.embedder.encode([c.text for c in chunks])
        self.chunks.extend(chunks)
        self.matrix = sp.vstack([self.matrix, m]).tocsr() if sp.issparse(m) else np.vstack([self.matrix, m])

    def search(self, query: str, k: int = 5) -> list[tuple[Chunk, float]]:
        q = self.embedder.encode([query])
        sims = self.matrix @ q.T
        sims = np.asarray(sims.todense()).ravel() if sp.issparse(sims) else np.asarray(sims).ravel()
        idx = np.argsort(-sims)[:k]
        return [(self.chunks[i], float(sims[i])) for i in idx]
