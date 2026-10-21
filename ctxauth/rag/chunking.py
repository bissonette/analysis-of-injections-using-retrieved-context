"""К5: предобработка и разбиение документов на фрагменты (чанки)."""
from __future__ import annotations

from dataclasses import dataclass

from ..text import n_tokens, split_sentences
from ..types import Chunk


@dataclass
class Document:
    doc_id: str
    text: str
    title: str = ""
    meta: dict | None = None


def chunk_document(doc: Document, max_words: int = 120, overlap_sentences: int = 0) -> list[Chunk]:
    """Разбиение по предложениям с ограничением длины чанка в словах.

    Перекрытие по умолчанию отключено, чтобы разметка «какой чанк содержит инъекцию»
    была однозначной; при перекрытии одна инъекция может попасть в два чанка.
    """
    # абзацы сохраняем как границы — они важны для ТК10 (распределённые инъекции)
    sents: list[str] = []
    for para in doc.text.split("\n\n"):
        sents.extend(split_sentences(para))
    chunks: list[Chunk] = []
    cur: list[str] = []
    cur_len = 0
    i = 0
    while i < len(sents):
        s = sents[i]
        L = n_tokens(s)
        if cur and cur_len + L > max_words:
            chunks.append(_mk(doc, cur, len(chunks)))
            cur = cur[-overlap_sentences:] if overlap_sentences else []
            cur_len = sum(n_tokens(x) for x in cur)
            continue
        cur.append(s)
        cur_len += L
        i += 1
    if cur:
        chunks.append(_mk(doc, cur, len(chunks)))
    return chunks


def _mk(doc: Document, sents: list[str], pos: int) -> Chunk:
    meta = dict(doc.meta or {})
    meta["title"] = doc.title
    return Chunk(chunk_id=f"{doc.doc_id}#{pos}", doc_id=doc.doc_id, text=" ".join(sents), position=pos, meta=meta)
