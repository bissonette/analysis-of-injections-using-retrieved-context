"""Baseline 1: детектор по ключевым словам/сигнатурам инъекций.

Повторяет распространённый практический подход «чёрный список фраз». Не зависит от запроса,
не различает полномочия — весь фрагмент блокируется при совпадении хотя бы одной сигнатуры.
Служит нижней границей для сравнения с семантическим контролем полномочий.
"""
from __future__ import annotations

import re

from ..text import normalize
from .base import BaseDefense
from ..types import Action, Chunk, Violation
from ..types import Permission as P

SIGNATURES = [
    r"ignore (all |the |your |any )?(previous|prior|above|preceding) (instructions|rules|prompts?)",
    r"disregard (the |your |all )?(previous|above|prior)",
    r"forget (your |the |all )?(previous|prior|earlier)",
    r"system prompt", r"you are now", r"from now on", r"developer mode",
    r"new instructions?", r"real task", r"instead of",
    r"reveal your", r"print your (instructions|prompt|configuration)",
    r"send .{0,30}(email|to)\b.{0,30}@", r"\bcall\b.{0,15}\btool\b",
    r"<\|im_start\|>", r"\[/?inst\]", r"<</?sys>>",
    r"игнорир", r"забудь .{0,20}(инструкц|указан)", r"системный промпт",
    r"новые инструкции", r"вместо", r"отправь .{0,20}письмо",
]
_RE = [re.compile(s, re.I) for s in SIGNATURES]


class KeywordDetector(BaseDefense):
    name = "keyword"

    def __init__(self, deobfuscate: bool = True):
        self.deobfuscate = deobfuscate

    def decide(self, query: str, chunk: Chunk):
        text = normalize(chunk.text, self.deobfuscate).text if self.deobfuscate else chunk.text
        for rx in _RE:
            if rx.search(text):
                return Action.BLOCK, None, [Violation(P.P3_INSTRUCTIONS, 1.0,
                                                       f"сигнатура: {rx.pattern[:40]}", chunk.text[:80])]
        return Action.PASS, None, []
