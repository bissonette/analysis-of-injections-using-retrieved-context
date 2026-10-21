"""Текстовые утилиты: разбиение на предложения, нормализация и деобфускация (против ТК9)."""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field

_SENT_RE = re.compile(r"(?<=[.!?…])\s+(?=[\"'«(\[A-ZА-ЯЁ0-9#<*\-])|\n+")
_WORD_RE = re.compile(r"\w+", re.UNICODE)

ZERO_WIDTH = dict.fromkeys(map(ord, "​‌‍⁠﻿­"), None)

# Кириллические/греческие омоглифы → латиница (для атак, маскирующих ключевые слова).
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O", "Р": "P",
    "С": "C", "Т": "T", "Х": "X", "ο": "o", "α": "a", "ε": "e", "ι": "i", "ν": "v",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{16,}={0,2})(?![A-Za-z0-9+/=])")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_HIDDEN_SPAN_RE = re.compile(
    r"<(span|div|p)[^>]*(display\s*:\s*none|font-size\s*:\s*0|color\s*:\s*(white|#fff\b|#ffffff))[^>]*>(.*?)</\1>",
    re.S | re.I,
)
_TAG_RE = re.compile(r"<[^>]{1,200}>")


def split_sentences(text: str) -> list[str]:
    parts = [p.strip() for p in _SENT_RE.split(text)]
    return [p for p in parts if p]


def words(text: str) -> list[str]:
    return _WORD_RE.findall(text.lower())


def n_tokens(text: str) -> int:
    """Грубая оценка числа токенов (по словам) — для метрики доли удалённого контекста."""
    return len(_WORD_RE.findall(text))


def _is_mostly_cyrillic(word: str) -> bool:
    cyr = sum(1 for ch in word if "а" <= ch.lower() <= "я" or ch.lower() == "ё")
    return cyr > len(word) / 2


def fold_homoglyphs(text: str) -> str:
    """Заменяет омоглифы только в словах, которые в основном латинские (русский текст не трогаем)."""

    def fix(m: re.Match) -> str:
        w = m.group(0)
        if _is_mostly_cyrillic(w):
            return w
        return "".join(_HOMOGLYPHS.get(ch, ch) for ch in w)

    return re.sub(r"\w+", fix, text)


def _looks_textual(b: bytes) -> str | None:
    try:
        s = b.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(ch.isprintable() or ch.isspace() for ch in s)
    if s and printable / len(s) > 0.95 and len(words(s)) >= 3:
        return s
    return None


@dataclass
class Normalized:
    text: str
    flags: list[str] = field(default_factory=list)
    revealed: list[str] = field(default_factory=list)  # скрытые/закодированные фрагменты, извлечённые явно


def normalize(text: str, deobfuscate: bool = True) -> Normalized:
    """Приводит текст к канонической форме, раскрывая типовые приёмы ТК9.

    Возвращает нормализованный текст и флаги обнаруженных приёмов сокрытия —
    сами по себе флаги не являются нарушением полномочий, но учитываются скорером.
    """
    flags: list[str] = []
    revealed: list[str] = []
    t = unicodedata.normalize("NFKC", text)
    if not deobfuscate:
        return Normalized(t, flags, revealed)
    if t.translate(ZERO_WIDTH) != t:
        flags.append("zero_width")
        t = t.translate(ZERO_WIDTH)
    for m in _HTML_COMMENT_RE.finditer(t):
        flags.append("html_comment")
        revealed.append(m.group(1).strip())
    for m in _HIDDEN_SPAN_RE.finditer(t):
        flags.append("hidden_markup")
        revealed.append(_TAG_RE.sub(" ", m.group(4)).strip())
    t = _HTML_COMMENT_RE.sub(lambda m: " " + m.group(1) + " ", t)
    t = _TAG_RE.sub(" ", t)
    folded = fold_homoglyphs(t)
    if folded != t:
        flags.append("homoglyph")
        t = folded
    for m in _B64_RE.finditer(t):
        blob = m.group(1)
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        s = _looks_textual(dec)
        if s:
            flags.append("base64")
            revealed.append(s)
            t = t.replace(blob, " " + s + " ")
    # leetspeak: раскрываем только «слова», где цифры перемешаны с буквами
    def unleet(m: re.Match) -> str:
        w = m.group(0)
        n_letters = len(re.findall(r"[A-Za-z]", w))
        n_leet = len(re.findall(r"[013457@$]", w))
        if n_letters >= 2 and n_leet >= 2 and len(w) >= 5:
            return w.translate(_LEET)
        return w

    t2 = re.sub(r"[\w@$]+", unleet, t)
    if t2 != t:
        flags.append("leet")
        t = t2
    t = re.sub(r"[ \t]+", " ", t)
    return Normalized(t.strip(), sorted(set(flags)), revealed)


URL_RE = re.compile(r"(?:https?://|www\.)[^\s)\]>\"']+", re.I)
MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\(([^)\s]+)[^)]*\)")


def extract_urls(text: str) -> list[str]:
    return URL_RE.findall(text)


def url_domain(url: str) -> str:
    u = re.sub(r"^https?://", "", url, flags=re.I)
    u = re.sub(r"^www\.", "", u, flags=re.I)
    return u.split("/")[0].split("?")[0].split(":")[0].lower()


def domain_allowed(domain: str, allowlist: frozenset[str] | set[str]) -> bool:
    return any(domain == d or domain.endswith("." + d) for d in allowlist)
