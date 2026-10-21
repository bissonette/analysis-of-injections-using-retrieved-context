"""К2 — оркестратор RAG-стенда: собирает конвейер К3–К12 и исполняет один запрос.

Через параметр `defense` подключается любой контроль полномочий (К8) или baseline —
всё, что реализует интерфейс BaseDefense (ctxauth.baselines.base).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..rag.audit import AuditLog
from ..rag.chunking import Document, chunk_document
from ..rag.embed import make_embedder
from ..rag.index import VectorIndex
from ..rag.llm import BaseLLM, SimulatedLLM
from ..rag.postprocess import PostprocessResult, postprocess
from ..rag.prompts import SYSTEM_PROMPT, build_user_message
from ..rag.retriever import Retriever
from ..rag.tools import ToolCall, ToolRegistrar
from ..types import Chunk, FilterResult


@dataclass
class RAGResult:
    query: str
    answer: str
    tool_calls: list[ToolCall]
    kept_chunks: list[Chunk]
    retrieved: list[Chunk]
    filter_result: FilterResult | None
    post: PostprocessResult
    latency_ms: float = 0.0


@dataclass
class Orchestrator:
    index: VectorIndex
    llm: BaseLLM = field(default_factory=SimulatedLLM)
    defense: Any = None        # BaseDefense | None (None → без фильтра)
    k: int = 5
    rerank: bool = False
    spotlight: bool = False     # архитектурная мера: маркировка недоверенного контекста
    tools: ToolRegistrar = field(default_factory=ToolRegistrar)
    audit: AuditLog | None = None

    def __post_init__(self):
        self.retriever = Retriever(self.index, k=self.k, rerank=self.rerank)

    @classmethod
    def from_documents(cls, docs: list[Document], *, embedder: str = "tfidf",
                       max_words: int = 60, **kw) -> "Orchestrator":
        chunks = [c for d in docs for c in chunk_document(d, max_words=max_words)]
        index = VectorIndex(make_embedder(embedder)).build(chunks)
        return cls(index=index, **kw)

    def answer(self, query: str, intent: str | None = None) -> RAGResult:
        import time
        t0 = time.perf_counter()
        retrieved = self.retriever.retrieve(query)
        fr = None
        if self.defense is not None:
            fr = self.defense.filter(query, retrieved, intent=intent)
            kept = fr.kept_chunks
        else:
            kept = retrieved
        self.tools.reset()
        user_msg = build_user_message(query, kept, self.tools.specs, spotlight=self.spotlight)
        out = self.llm.generate(SYSTEM_PROMPT, user_msg, query=query, chunks=kept, tools=self.tools.specs)
        for call in out.tool_calls:
            self.tools.call(call)
        allowlist = fr.policy.domain_allowlist if (fr and fr.policy) else frozenset()
        post = postprocess(out.text, allowlist)
        res = RAGResult(query, post.text, out.tool_calls, kept, retrieved, fr, post,
                        latency_ms=(time.perf_counter() - t0) * 1000)
        if self.audit is not None:
            self.audit.write("answer", query=query, kept=[c.chunk_id for c in kept],
                             tool_calls=[c.name for c in out.tool_calls], blocked_urls=post.blocked_urls)
        return res
