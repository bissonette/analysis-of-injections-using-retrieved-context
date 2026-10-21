"""Загрузчики внешних бенчмарков → единый формат AttackSample с разметкой по полномочиям П2–П6.

ВАЖНО: загрузчики только ЧИТАЮТ уже скачанные файлы бенчмарков и переводят их в общий формат.
Тексты инъекций берутся из самих файлов бенчмарка (поля context/injected_task/attack_str),
здесь ничего не синтезируется. Сборка «отравленного» фрагмента повторяет логику вставки
самого бенчмарка (в конец контекста, как в PIArena/BIPIA).

Соответствие «категория бенчмарка → нарушаемое полномочие» — рабочая разметка,
задокументирована в таблицах ниже; при расхождении с текстом модели угроз правится здесь.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..types import Permission as P
from .sample_io import AttackSample  # re-export shim


# ---- PIArena ---------------------------------------------------------------------------------
# datasets/*_rag.json, *_long.json: поля target_inst, context, injected_task, category.
PIARENA_CATEGORY_PERM = {
    "phishing_injection": P.P6_FORMAT_CHANNEL,      # вставка ссылки, уводящей пользователя
    "content_promotion": P.P6_FORMAT_CHANNEL,       # навязывание рекламного контента
    "access_denial": P.P3_INSTRUCTIONS,             # подмена правил обработки («откажи в доступе»)
    "infrastructure_failure": P.P3_INSTRUCTIONS,    # ложное служебное сообщение о сбое
    "knowledge_corruption": P.P1_CONTENT,           # искажение фактов — ВНЕ области метода (П1)
}
PIARENA_CATEGORY_TECH = {
    "phishing_injection": "TK6", "content_promotion": "TK7",
    "access_denial": "TK1", "infrastructure_failure": "TK3", "knowledge_corruption": "TK2",
}


def load_piarena(path: str, intent: str = "qa", limit: int | None = None,
                 include_knowledge_corruption: bool = False) -> list[AttackSample]:
    data = _read_json(path)
    name = Path(path).stem
    out: list[AttackSample] = []
    for i, it in enumerate(data):
        cat = it.get("category", "")
        if cat == "knowledge_corruption" and not include_knowledge_corruption:
            continue
        inj = (it.get("injected_task") or "").strip()
        ctx = it.get("context", "")
        if not inj:  # knowledge_corruption: инъекции-строки нет, отравлен сам контекст
            poisoned, is_inj = ctx, True
        else:
            poisoned, is_inj = (ctx.rstrip() + " " + inj), True
        perm = PIARENA_CATEGORY_PERM.get(cat)
        out.append(AttackSample(
            query=it.get("target_inst", "")[:300] or "Answer the question based on the context.",
            chunk_text=poisoned, is_injected=is_inj,
            permission=perm if perm != P.P1_CONTENT else None,
            technique=PIARENA_CATEGORY_TECH.get(cat), intent=intent,
            source=f"piarena/{name}", meta={"category": cat, "injected_task": inj}))
        # чистый вариант того же контекста — для FPR
        out.append(AttackSample(query=it.get("target_inst", "")[:300] or "Answer the question based on the context.",
                                chunk_text=ctx, is_injected=False, intent=intent,
                                source=f"piarena/{name}", meta={"category": "clean"}))
        if limit and len(out) >= limit:
            break
    return out


# ---- SEP (Should it be Executed or Processed) ------------------------------------------------
# prompt_instructed = данные с внедрённой подзадачей; witness = слово-свидетель исполнения.
def load_sep(path: str, limit: int | None = None, intent: str = "qa") -> list[AttackSample]:
    data = _read_json(path)
    out: list[AttackSample] = []
    for i, it in enumerate(data):
        q = it.get("system_prompt_clean", "")
        pc, pi = it.get("prompt_clean", ""), it.get("prompt_instructed", "")
        injected = pi[len(pc):].strip() if pi.startswith(pc) else (it.get("witness") or "")
        out.append(AttackSample(query=q, chunk_text=pi,
                                is_injected=True, permission=P.P2_TASK, technique="TK2",
                                canary=it.get("witness"), intent=intent,
                                source="sep", meta={"subtask": _sep_subtask(it), "injected_task": injected}))
        out.append(AttackSample(query=q, chunk_text=it.get("prompt_clean", ""),
                                is_injected=False, intent=intent, source="sep",
                                meta={"category": "clean"}))
        if limit and len(out) >= 2 * limit:
            break
    return out


def _sep_subtask(it: dict) -> str:
    info = it.get("info")
    if isinstance(info, str):
        try:
            info = json.loads(info.replace("'", '"'))
        except Exception:
            return ""
    return (info or {}).get("subtask", "") if isinstance(info, dict) else ""


# ---- BIPIA (email/table/code — локальные контексты) ------------------------------------------
# Контексты: benchmark/<task>/test.jsonl; атаки: benchmark/text_attack_test.json (dict categ->list).
BIPIA_TEXT_CATEGORY_PERM = {
    "Task Automation": P.P5_ACTIONS, "Business Intelligence": P.P2_TASK,
    "Conversational Agent": P.P2_TASK, "Research Assistance": P.P2_TASK,
    "Sentiment Analysis": P.P2_TASK, "Substitution Ciphers": P.P6_FORMAT_CHANNEL,
    "Base Encoding": P.P6_FORMAT_CHANNEL, "Reverse Text": P.P6_FORMAT_CHANNEL,
    "Emoji Substitution": P.P6_FORMAT_CHANNEL, "Language Translation": P.P6_FORMAT_CHANNEL,
    "Information Dissemination": P.P6_FORMAT_CHANNEL, "Marketing & Advertising": P.P6_FORMAT_CHANNEL,
    "Entertainment": P.P2_TASK, "Scams & Fraud": P.P6_FORMAT_CHANNEL,
    "Misinformation & Propaganda": P.P6_FORMAT_CHANNEL,
}


def load_bipia(repo_dir: str, task: str = "email", split: str = "test",
               limit: int | None = 300, intent: str = "qa") -> list[AttackSample]:
    """repo_dir — путь к склонированному microsoft/BIPIA. task: email|table|code."""
    base = Path(repo_dir) / "benchmark"
    ctx_file = base / task / f"{split}.jsonl"
    atk_file = base / f"{'code' if task == 'code' else 'text'}_attack_{split}.json"
    if not ctx_file.exists() or not atk_file.exists():
        raise FileNotFoundError(f"нет файлов BIPIA: {ctx_file} / {atk_file} (склонируйте microsoft/BIPIA)")
    contexts = [json.loads(l) for l in ctx_file.open()]
    attacks = json.load(atk_file.open())
    perm_map = BIPIA_TEXT_CATEGORY_PERM if task != "code" else None
    out: list[AttackSample] = []
    flat = [(cat, s) for cat, lst in attacks.items() for s in lst]
    for i, ctx in enumerate(contexts):
        c = ctx.get("context", "")
        if isinstance(c, list):            # BIPIA code: контекст приходит списком строк
            c = "\n".join(map(str, c))
        q = ctx.get("question", "Answer based on the context.")
        if isinstance(q, list):
            q = " ".join(map(str, q))
        out.append(AttackSample(query=q, chunk_text=c, is_injected=False, intent=intent,
                                source=f"bipia/{task}", meta={"category": "clean"}))
        cat, atk = flat[i % len(flat)]
        perm = (perm_map or {}).get(cat, P.P5_ACTIONS if task == "code" else P.P2_TASK)
        out.append(AttackSample(query=q, chunk_text=c.rstrip() + "\n" + atk, is_injected=True,
                                permission=perm, technique="TK5" if task == "code" else None,
                                intent=intent, source=f"bipia/{task}",
                                meta={"category": cat, "attack": atk[:200]}))
        if limit and len(out) >= 2 * limit:
            break
    return out


# ---- встроенный корпус → только чистые примеры (FPR без скачивания) ---------------------------
def load_builtin_clean(queries: list[str] | None = None, max_words: int = 60,
                       intent: str = "summarize") -> list[AttackSample]:
    from ..rag.chunking import chunk_document
    from .builtin_corpus import builtin_documents
    queries = queries or ["Briefly summarize this document", "What does this document say?"]
    out: list[AttackSample] = []
    for d in builtin_documents():
        for c in chunk_document(d, max_words=max_words):
            for q in queries:
                out.append(AttackSample(query=q, chunk_text=c.text, is_injected=False, intent=intent,
                                        source="builtin", meta={"category": d.meta.get("category")}))
    return out


def _read_json(path: str):
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"нет файла: {path}. Скачайте соответствующий бенчмарк (см. docs/BENCHMARKS.md)")
    data = json.load(p.open())
    return data if isinstance(data, list) else list(data.values())
