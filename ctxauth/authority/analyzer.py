"""Построение профиля заявляемого влияния фрагмента (AuthorityProfile).

Комбинирует правиловый и обучаемый скореры на нормализованном (деобфусцированном) тексте.
"""
from __future__ import annotations

import re

from ..text import extract_urls, normalize, split_sentences
from ..types import CONTROLLED, AuthorityProfile, Chunk, SentenceEvidence
from ..types import Permission as P
from .ml import MLScorer
from .rules import RuleScorer

# Глагольные указания на действия → инструмент стенда (для проверки области делегирования П5).
TOOL_HINTS: tuple[tuple[str, str], ...] = (
    (r"\b(send|forward|e-?mail)\b.{0,40}(@|\bmail\b|\be-?mail\b)|\bsend_email\b|отправь\w*.{0,20}письм", "send_email"),
    (r"\bhttp_get\b|\b(http|web|get|post)\s+request\b|\bfetch\b.{0,20}\burl\b|\bvisit\b.{0,20}https?://", "http_get"),
    (r"\bexport_db\b|\b(export|dump|upload|exfiltrate|выгрузи\w*|экспортир\w*)\b.{0,30}\b(database|table|records|data|баз\w*|таблиц\w*)", "export_db"),
    (r"\bdelete_record\b|\b(delete|drop|wipe|erase|purge|удали\w*)\b.{0,25}\b(record|table|account|user|запис\w*|таблиц\w*)", "delete_record"),
    (r"\bcreate_ticket\b|\b(create|open|file|raise|заведи|создай)\w*\b.{0,20}\b(ticket|incident|заявк\w*|тикет\w*)", "create_ticket"),
    (r"\bsearch_kb\b|\bsearch\b.{0,20}\bknowledge base\b", "search_kb"),
)
_TOOL_RE = [(re.compile(p, re.I), name) for p, name in TOOL_HINTS]
_HIDDEN_FLAGS = {"zero_width", "html_comment", "hidden_markup", "base64", "homoglyph", "leet"}


def detect_tools(text: str) -> list[str]:
    return sorted({name for rx, name in _TOOL_RE if rx.search(text)})


class AuthorityAnalyzer:
    """mode: 'rules' | 'ml' | 'max' | 'mean' — способ комбинирования скореров."""

    def __init__(self, ml: MLScorer | None = None, rules: RuleScorer | None = None,
                 mode: str = "max", deobfuscate: bool = True, hidden_boost: float = 0.2,
                 gate: float = 0.8, rule_floor: float = 0.2):
        if mode in ("ml", "max", "mean", "gated") and ml is None:
            raise ValueError(f"режим {mode} требует обученный MLScorer")
        self.ml, self.rules = ml, rules or RuleScorer()
        self.mode, self.deobfuscate, self.hidden_boost = mode, deobfuscate, hidden_boost
        # для режима "gated": ML усиливает правила, но в одиночку (когда правила молчат)
        # учитывается только при уверенности ≥ gate — это снижает ложные вне распределения.
        self.gate, self.rule_floor = gate, rule_floor

    # --- оценка набора «сырых» предложений ------------------------------------------------
    def score_sentences(self, raw: list[str]) -> list[SentenceEvidence]:
        norms = [normalize(s, self.deobfuscate) for s in raw]
        texts = [n.text for n in norms]
        ml_scores = self.ml.predict(texts) if (self.ml is not None and self.mode != "rules") else [None] * len(texts)
        out = []
        for s, n, m in zip(raw, norms, ml_scores):
            r, hits, rflags = self.rules.score(n.text)
            for extra in n.revealed:  # скрытые фрагменты оцениваем отдельно — они не «размываются» соседним текстом
                r2, _, _ = self.rules.score(extra)
                for p, v in r2.items():
                    r[p] = max(r.get(p, 0.0), v)
            scores = {}
            for p in CONTROLLED:
                rv = r.get(p, 0.0)
                mv = m.get(p, 0.0) if m is not None else 0.0
                if self.mode == "rules":
                    v = rv
                elif self.mode == "ml":
                    v = mv
                elif self.mode == "mean":
                    v = 0.5 * (rv + mv)
                elif self.mode == "gated":
                    # правила сработали → ML может подтвердить/усилить; правила молчат →
                    # ML учитывается только при высокой уверенности (gate).
                    v = max(rv, mv) if rv >= self.rule_floor else (mv if mv >= self.gate else 0.0)
                else:  # max
                    v = max(rv, mv)
                scores[p] = v
            flags = list(n.flags) + rflags
            if _HIDDEN_FLAGS & set(n.flags) and max(scores.values()) > 0.2:
                scores = {p: min(1.0, v + self.hidden_boost) if v > 0.2 else v for p, v in scores.items()}
            out.append(SentenceEvidence(
                text=s, scores=scores, tools=detect_tools(n.text),
                urls=extract_urls(n.text), flags=sorted(set(flags)),
            ))
        return out

    def score_text(self, text: str) -> SentenceEvidence:
        return self.score_sentences([text])[0]

    def analyze_chunk(self, chunk: Chunk, sentences: list[str] | None = None,
                      evidence: list[SentenceEvidence] | None = None) -> AuthorityProfile:
        sentences = sentences if sentences is not None else split_sentences(chunk.text)
        evidence = evidence if evidence is not None else self.score_sentences(sentences)
        claimed = {p: max((e.scores.get(p, 0.0) for e in evidence), default=0.0) for p in CONTROLLED}
        return AuthorityProfile(claimed=claimed, sentences=evidence)
