"""Бэкенды LLM.

* SimulatedLLM — детерминированная «наихудшая» модель для офлайн-экспериментов:
  отвечает экстрактивно и ВСЕГДА (с вероятностью compliance) исполняет инъекцию,
  если её ключевое предложение дошло до контекста. ASR такой модели = доля доставленных
  атак (payload delivery rate) — верхняя оценка, не зависящая от «послушности» конкретной LLM.
* OpenAICompatibleLLM — любой OpenAI-совместимый сервер (Ollama, vLLM, llama.cpp server):
  локальный инференс реальной модели.
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
from .tools import CALL_LINE, ToolCall, parse_tool_calls


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


class LLMUnavailable(RuntimeError):
    """Сервер модели недоступен / модель не найдена — с понятным пояснением, что делать."""


class OpenAICompatibleLLM(BaseLLM):
    """Например: base_url=http://localhost:11434/v1, model=qwen2.5:7b-instruct (Ollama).

    Рассчитан на долгие прогоны на домашнем компьютере:
      * длинный таймаут (первый запрос к Ollama загружает модель в память — на CPU это минуты);
      * повторы с нарастающей паузой при таймауте/обрыве/ошибке 5xx;
      * ограничение длины ответа (max_tokens) — иначе модель на CPU может «писать» минутами;
      * check_server() и warmup() — проверка и прогрев до начала основного цикла.
    """

    name = "openai-compatible"

    def __init__(self, model: str, base_url: str = "http://localhost:11434/v1",
                 api_key: str | None = None, temperature: float = 0.0, timeout: float = 600,
                 max_tokens: int = 400, retries: int = 3, backoff: float = 10.0):
        if not model:
            raise ValueError("не указана модель (--model), например qwen2.5:7b-instruct")
        self.model, self.base_url = model, base_url.rstrip("/")
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "none")
        self.temperature, self.timeout = temperature, timeout
        self.max_tokens, self.retries, self.backoff = max_tokens, retries, backoff
        self.name = f"{self.model}"

    # --- низкоуровневый HTTP ------------------------------------------------------------
    def _request(self, path: str, body: dict | None, timeout: float) -> dict:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"{self.base_url}{path}", data=data, headers={
            "Content-Type": "application/json", "Authorization": f"Bearer {self.api_key}"},
            method="POST" if data is not None else "GET")
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8"))

    def _list_models(self) -> list[str]:
        data = self._request("/models", None, timeout=30)
        return [m.get("id", "") for m in data.get("data", [])]

    def _complete(self, system: str, user: str, max_tokens: int, timeout: float) -> str:
        body = {
            "model": self.model, "temperature": self.temperature, "max_tokens": max_tokens,
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._request("/chat/completions", body, timeout)
        return data["choices"][0]["message"]["content"] or ""

    def check_server(self) -> list[str]:
        """Проверить, что сервер жив и модель скачана. Возвращает список доступных моделей."""
        import urllib.error
        try:
            names = self._list_models()
        except urllib.error.URLError as e:
            raise LLMUnavailable(
                f"Сервер модели не отвечает по адресу {self.base_url} ({e.reason}). "
                "Запустите Ollama (приложение или команда `ollama serve`) и повторите.") from e
        except (TimeoutError, OSError) as e:
            raise LLMUnavailable(f"Сервер модели не отвечает по адресу {self.base_url}: {e}") from e
        base = self.model.split(":")[0]
        if names and self.model not in names and not any(n.split(":")[0] == base for n in names):
            raise LLMUnavailable(
                f"Модель {self.model} не найдена на сервере. Скачайте её: `ollama pull {self.model}`. "
                f"Доступны: {', '.join(names) or '—'}")
        return names

    def warmup(self) -> float:
        """Первый запрос: загрузка модели в память. Возвращает время в секундах."""
        import time
        t0 = time.perf_counter()
        self.chat("You are a helpful assistant.", "Reply with the single word OK.",
                  max_tokens=5, timeout=max(self.timeout, 900))
        return time.perf_counter() - t0

    def chat(self, system: str, user: str, *, max_tokens: int | None = None,
             timeout: float | None = None) -> str:
        import time
        import urllib.error
        last: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                return self._complete(system, user, max_tokens or self.max_tokens, timeout or self.timeout)
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    raise LLMUnavailable(
                        f"Модель {self.model} не найдена: `ollama pull {self.model}`") from e
                if e.code < 500:
                    raise
                last = e
            except (TimeoutError, urllib.error.URLError, ConnectionError, OSError) as e:
                last = e
            if attempt < self.retries:
                time.sleep(self.backoff * (3 ** attempt))  # 10 с, 30 с, 90 с …
        raise LLMUnavailable(
            f"Модель не ответила после {self.retries + 1} попыток (последняя ошибка: {last!r}). "
            "Если компьютер медленный — увеличьте --timeout или возьмите модель поменьше "
            "(qwen2.5:3b-instruct).") from last

    def generate(self, system, user, *, query, chunks, tools):
        raw = self.chat(system, user)
        calls = parse_tool_calls(raw)
        text = "\n".join(l for l in raw.splitlines() if not CALL_LINE.match(l))
        return LLMOutput(text=text, tool_calls=calls, raw=raw)


class OllamaLLM(OpenAICompatibleLLM):
    """Родной API Ollama (/api/chat). В отличие от OpenAI-совместимого, позволяет задать окно
    контекста num_ctx в каждом запросе: по умолчанию Ollama держит короткое окно и молча
    обрезает длинный запрос — вместе с инъекцией. С num_ctx=8192 длинные фрагменты RAG-наборов
    помещаются целиком. Адрес можно указывать как http://localhost:11434 или .../v1."""

    name = "ollama"

    def __init__(self, model: str, base_url: str = "http://localhost:11434", num_ctx: int = 8192,
                 **kw):
        base = base_url.rstrip("/")
        base = base[:-3] if base.endswith("/v1") else base
        super().__init__(model, base_url=base, **kw)
        self.num_ctx = num_ctx

    def _list_models(self) -> list[str]:
        data = self._request("/api/tags", None, timeout=30)
        return [m.get("name") or m.get("model", "") for m in data.get("models", [])]

    def _complete(self, system: str, user: str, max_tokens: int, timeout: float) -> str:
        body = {
            "model": self.model, "stream": False,
            "options": {"temperature": self.temperature, "num_predict": max_tokens, "num_ctx": self.num_ctx},
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
        }
        data = self._request("/api/chat", body, timeout)
        return (data.get("message") or {}).get("content") or ""


def make_llm(cfg: dict | None, registry: dict[str, PayloadSpec] | None = None) -> BaseLLM:
    cfg = dict(cfg or {"backend": "sim"})
    backend = cfg.pop("backend", "sim")
    if backend == "sim":
        return SimulatedLLM(registry=registry, **cfg)
    if backend == "ollama":
        return OllamaLLM(**cfg)
    if backend in ("openai", "openai-compatible"):
        cfg.pop("num_ctx", None)
        return OpenAICompatibleLLM(**cfg)
    raise ValueError(f"неизвестный LLM-бэкенд: {backend}")
