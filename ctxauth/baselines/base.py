"""Единый интерфейс защиты: filter(query, chunks, intent) -> FilterResult.

Метод К8 (ContextAuthorityController) и все baseline'ы реализуют его, поэтому протокол
оценки (ctxauth.eval) одинаково прогоняет любой из них.
"""
from __future__ import annotations

import time

from ..types import Action, AuthorityProfile, Chunk, ChunkDecision, FilterResult


class BaseDefense:
    name = "base"

    def decide(self, query: str, chunk: Chunk) -> tuple[Action, str | None, list]:
        """Вернуть (действие, текст_при_sanitize, список_нарушений) для одного фрагмента."""
        raise NotImplementedError

    def filter(self, query: str, chunks: list[Chunk], intent: str | None = None) -> FilterResult:
        t0 = time.perf_counter()
        decisions = []
        for c in chunks:
            action, text, viol = self.decide(query, c)
            prof = AuthorityProfile(claimed={}, sentences=[])
            decisions.append(ChunkDecision(c, action, prof, viol, sanitized_text=text))
        return FilterResult(None, decisions, latency_ms=(time.perf_counter() - t0) * 1000)


class PassthroughFilter(BaseDefense):
    """Ничего не фильтрует (нужен как заглушка там, где defense обязателен)."""

    name = "no_filter"

    def decide(self, query, chunk):
        return Action.PASS, None, []


# Алиас: в оркестраторе «без фильтра» = defense=None, но для единообразия метрик удобно иметь объект.
NoFilterDefense = PassthroughFilter
