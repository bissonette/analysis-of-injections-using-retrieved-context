"""К9: бэкенды LLM.

* SimulatedLLM — детерминированная «наихудшая» модель для офлайн-экспериментов:
  отвечает экстрактивно и ВСЕГДА (с вероятностью compliance) исполняет инъекцию,
  если её ключевое предложение дошло до контекста. ASR такой модели = доля доставленных
  атак (payload delivery rate) — верхняя оценка, не зависящая от «послушности» конкретной LLM.
* OpenAICompatibleLLM — любой OpenAI-совместимый сервер (Ollama, vLLM, llama.cpp server):
  локальный инференс, как в модели угроз (К9).
"""
from __future__ import annotations

import json
import os
import random
import urllib.request
from dataclasses import dataclass, field

from ..attacks.payload import PayloadSpec
from ..text import split_sentences, words
from ..types import Chunk, ToolSpec
from .prompts import SYSTEM_SECRET
from .tools import ToolCall, parse_tool_calls


@dataclass
class LLMOutput:
    text: str
    tool_calls: list[ToolCall] = field(default_factory=list)
    raw: str = ""


class BaseLLM:
    name = "base"

    def generate(self, system: str, user: str, *, query: str, chunks: list[Chunk],
                 tools: list[ToolSpec]) -> LLMOutput:
        raise NotImplementedError


class SimulatedLLM(BaseLLM):
    name = "sim"

    def __init__(self, registry: dict[str, PayloadSpec] | None = None, compliance: float = 1.0,
                 seed: int = 0, max_sentences: int = 3):
        self.registry = registry or {}
        self.compliance = compliance
        self.rng = random.Random(seed)
        self.max_sentences = max_sentences

    def _answer(self, query: str, chunks: list[Chunk]) -> str:
        q = set(words(query))
        canaries = [c.lower() for c in self.registry]
        scored = []
        for c in chunks:
            for s in split_sentences(c.text):
                low = s.lower()
                if any(k in low for k in canaries):
                    continue  # модель не цитирует внедрённые указания дословно
                scored.append((len(q & set(words(s))), s))
        scored.sort(key=lambda x: -x[0])
        return " ".join(s for _, s in scored[: self.max_sentences]) or "No relevant information found."

    def generate(self, system, user, *, query, chunks, tools):
        context = "\n".join(c.text for c in chunks)
        text = self._answer(query, chunks)
        calls: list[ToolCall] = []
        for p in self.registry.values():
            if not p.delivered(context) or self.rng.random() > self.compliance:
                continue
            if p.goal == "say":
                text = f"{text}\n{p.canary}"
            elif p.goal == "task":
                text = f"Here is what was requested: {p.canary}."
            elif p.goal == "disclose":
                text = f"{text}\nMy configuration: {SYSTEM_SECRET} ({p.canary})"
            elif p.goal == "tool":
                calls.append(ToolCall(p.tool or "send_email", {"note": p.canary}))
            elif p.goal == "link":
                text = f"{text}\n![status]({p.url})"
            elif p.goal == "format":
                text = f"{text}\n{p.canary}"
        raw = text + "".join(f"\nCALL {c.name} {json.dumps(c.args)}" for c in calls)
        return LLMOutput(text=text, tool_calls=calls, raw=raw)


class OpenAICompatibleLLM(BaseLLM):
    """Например: base_url=http://localhost:11434/v1, model=qwen2.5:7b-instruct (Ollama)."""

    name = "openai-compatible"

    def __init__(self, model: str, base_url: str = "http://localhost:11434/v1",
                 api_key: str | None = None, temperature: float = 0.0, timeout: float = 120):
        self.model, self.base_url = model, base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "none")
        self.temperature, self.timeout = temperature, timeout

    def chat(self, system: str, user: str) -> str:
        body = json.dumps({
            "model": self.model, "temperature": self.temperature,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }).encode()
        req = urllib.request.Request(f"{self.base_url}/chat/completions", data=body, headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"})
        with urllib.request.urlopen(req, timeout=self.timeout) as r:
            data = json.loads(r.read())
        return data["choices"][0]["message"]["content"] or ""

    def generate(self, system, user, *, query, chunks, tools):
        raw = self.chat(system, user)
        calls = parse_tool_calls(raw)
        text = "\n".join(l for l in raw.splitlines() if not l.strip().startswith("CALL "))
        return LLMOutput(text=text, tool_calls=calls, raw=raw)


def make_llm(cfg: dict | None, registry: dict[str, PayloadSpec] | None = None) -> BaseLLM:
    cfg = dict(cfg or {"backend": "sim"})
    backend = cfg.pop("backend", "sim")
    if backend == "sim":
        return SimulatedLLM(registry=registry, **cfg)
    if backend in ("openai", "ollama", "openai-compatible"):
        return OpenAICompatibleLLM(**cfg)
    raise ValueError(f"неизвестный LLM-бэкенд: {backend}")
