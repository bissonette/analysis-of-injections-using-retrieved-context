"""Эксперимент Б: полноценный RAG-цикл с реальным поиском.

В отличие от «Эксперимента А» (атакующий фрагмент гарантированно помещается в контекст),
здесь отравленный документ ИНДЕКСИРУЕТСЯ в общий корпус вместе с чистыми документами,
затем выполняется обычный поиск по запросу пользователя. Измеряется:

  * Hit@k            — доля атак, чей отравленный фрагмент попал в top-k выдачи;
  * ASR (без фильтра) — доля атак, чья инъекция оказалась в передаваемом контексте;
  * ASR (с фильтром)  — то же после контроля разрешений;
  * ASR | hit         — успех при условии попадания в выдачу (изолирует вклад фильтра).

Атака не может подействовать, если её фрагмент не попал в выдачу, — поэтому end-to-end
успех с учётом поиска ниже, чем при гарантированном включении.
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field

from ..rag.chunking import Document, chunk_document
from ..rag.embed import make_embedder
from ..rag.index import VectorIndex
from ..rag.retriever import Retriever
from .harness import _injection_survives
from .sample import AttackSample


@dataclass
class RetrievalReport:
    n_attacks: int
    n_corpus_docs: int
    k: int
    hit_at_k: float
    asr_no_filter: float
    asr_filter: float
    asr_given_hit_no_filter: float
    asr_given_hit_filter: float
    by_source: dict = field(default_factory=dict)

    def summary(self) -> str:
        return (f"[retrieval k={self.k}] атак={self.n_attacks} корпус={self.n_corpus_docs} док. | "
                f"Hit@{self.k}={self.hit_at_k:.2f} | ASR {self.asr_no_filter:.2f} -> {self.asr_filter:.2f} "
                f"| при попадании: {self.asr_given_hit_no_filter:.2f} -> {self.asr_given_hit_filter:.2f}")

    def to_dict(self) -> dict:
        return {k: getattr(self, k) for k in ("n_attacks", "n_corpus_docs", "k", "hit_at_k",
                "asr_no_filter", "asr_filter", "asr_given_hit_no_filter", "asr_given_hit_filter",
                "by_source")}


def run_retrieval_experiment(samples: list[AttackSample], defense, k: int = 5,
                             max_attacks: int = 400, max_clean: int = 600,
                             max_words: int = 120, seed: int = 0) -> RetrievalReport:
    rng = random.Random(seed)
    attacks = [s for s in samples if s.is_injected
               and (s.meta.get("injected_task") or s.meta.get("attack"))]
    clean = [s for s in samples if not s.is_injected]
    rng.shuffle(attacks)
    rng.shuffle(clean)
    attacks = attacks[:max_attacks]
    clean = clean[:max_clean]

    # Корпус: отравленные документы + чистые документы бенчмарков + фоновый встроенный корпус.
    docs: list[Document] = []
    for i, s in enumerate(attacks):
        docs.append(Document(doc_id=f"atk{i}", text=s.chunk_text))
    for i, s in enumerate(clean):
        docs.append(Document(doc_id=f"cln{i}", text=s.chunk_text))
    from ..data.builtin_corpus import builtin_documents
    docs.extend(builtin_documents())

    chunks = [c for d in docs for c in chunk_document(d, max_words=max_words)]
    retriever = Retriever(VectorIndex(make_embedder("tfidf")).build(chunks), k=k)

    hits = succ_no = succ_f = hit_succ_no = hit_succ_f = 0
    by_src: dict = {}
    for i, s in enumerate(attacks):
        inj = (s.meta.get("injected_task") or s.meta.get("attack")).strip()
        retrieved = retriever.retrieve(s.query)
        hit = any(c.doc_id == f"atk{i}" and _injection_survives(c.text, inj) for c in retrieved)
        s_no = any(_injection_survives(c.text, inj) for c in retrieved)
        fr = defense.filter(s.query, retrieved, intent=s.intent)
        kept_text = "\n".join(c.text for c in fr.kept_chunks)
        s_f = _injection_survives(kept_text, inj)
        hits += hit
        succ_no += s_no
        succ_f += s_f
        if hit:
            hit_succ_no += s_no
            hit_succ_f += s_f
        d = by_src.setdefault(s.source, [0, 0, 0, 0])
        d[0] += 1
        d[1] += hit
        d[2] += s_no
        d[3] += s_f

    n = len(attacks)
    return RetrievalReport(
        n_attacks=n, n_corpus_docs=len(docs), k=k,
        hit_at_k=hits / n if n else 0.0,
        asr_no_filter=succ_no / n if n else 0.0,
        asr_filter=succ_f / n if n else 0.0,
        asr_given_hit_no_filter=hit_succ_no / hits if hits else 0.0,
        asr_given_hit_filter=hit_succ_f / hits if hits else 0.0,
        by_source={src: {"n": v[0], "hit_at_k": round(v[1] / v[0], 3),
                         "asr_no_filter": round(v[2] / v[0], 3), "asr_filter": round(v[3] / v[0], 3)}
                   for src, v in sorted(by_src.items())},
    )
