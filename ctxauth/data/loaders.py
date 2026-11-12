"""Загрузчики внешних бенчмарков → единый формат AttackSample с разметкой по виду навязываемого влияния.

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
    "phishing_injection": P.FORMAT,      # вставка ссылки, уводящей пользователя
    "content_promotion": P.FORMAT,       # навязывание рекламного контента
    "access_denial": P.INSTRUCTIONS,             # подмена правил обработки («откажи в доступе»)
    "infrastructure_failure": P.INSTRUCTIONS,    # ложное служебное сообщение о сбое
    "knowledge_corruption": P.CONTENT,           # искажение фактов — вне области метода (это content)
}
PIARENA_CATEGORY_TECH = {
    "phishing_injection": "exfiltration", "content_promotion": "content_insert",
    "access_denial": "override", "infrastructure_failure": "fake_system", "knowledge_corruption": "task_swap",
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
            permission=perm if perm != P.CONTENT else None,
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
        if pi.startswith(pc):
            injected = pi[len(pc):].strip()          # проба добавлена в конец данных
        elif pi.endswith(pc):
            injected = pi[: len(pi) - len(pc)].strip()  # проба добавлена в начало
        else:
            injected = ""  # позиция неизвестна — оценка доставки по решению фильтра целиком
        out.append(AttackSample(query=q, chunk_text=pi,
                                is_injected=True, permission=P.TASK, technique="task_swap",
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
    "Task Automation": P.ACTIONS, "Business Intelligence": P.TASK,
    "Conversational Agent": P.TASK, "Research Assistance": P.TASK,
    "Sentiment Analysis": P.TASK, "Substitution Ciphers": P.FORMAT,
    "Base Encoding": P.FORMAT, "Reverse Text": P.FORMAT,
    "Emoji Substitution": P.FORMAT, "Language Translation": P.FORMAT,
    "Information Dissemination": P.FORMAT, "Marketing & Advertising": P.FORMAT,
    "Entertainment": P.TASK, "Scams & Fraud": P.FORMAT,
    "Misinformation & Propaganda": P.FORMAT,
}


def load_bipia(repo_dir: str, task: str = "email", split: str = "test",
               limit: int | None = 300, intent: str = "qa", obfuscate: bool = False) -> list[AttackSample]:
    """repo_dir — путь к склонированному microsoft/BIPIA. task: email|table|code.

    obfuscate=True повторяет «stealth»-режим BIPIA: текст инъекции кодируется в base64,
    чтобы проверить устойчивость к обфускации (техника obfuscation).
    """
    import base64
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
    src = f"bipia/{task}" + ("_obf" if obfuscate else "")
    for i, ctx in enumerate(contexts):
        c = ctx.get("context", "")
        if isinstance(c, list):            # BIPIA code: контекст приходит списком строк
            c = "\n".join(map(str, c))
        q = ctx.get("question", "Answer based on the context.")
        if isinstance(q, list):
            q = " ".join(map(str, q))
        out.append(AttackSample(query=q, chunk_text=c, is_injected=False, intent=intent,
                                source=src, meta={"category": "clean"}))
        cat, atk = flat[i % len(flat)]
        perm = (perm_map or {}).get(cat, P.ACTIONS if task == "code" else P.TASK)
        payload = base64.b64encode(atk.encode()).decode() if obfuscate else atk
        out.append(AttackSample(query=q, chunk_text=c.rstrip() + "\n" + payload, is_injected=True,
                                permission=perm, technique="obfuscation" if obfuscate else ("tool_call" if task == "code" else None),
                                intent=intent, source=src,
                                meta={"category": cat, "attack": atk[:200], "obfuscated": obfuscate}))
        if limit and len(out) >= 2 * limit:
            break
    return out


# ---- InjecAgent (атаки на вызовы инструментов — вид влияния actions) -------------------------
# Инъекция сидит в ответе инструмента (поле отзыва); шаблон содержит плейсхолдер <Attacker Instruction>.
_INJECAGENT_BENIGN_REVIEW = "Great product overall, works as described and arrived on time."


def load_injecagent(repo_dir: str, variant: str = "dh", split: str = "base",
                    limit: int | None = None, intent: str = "qa") -> list[AttackSample]:
    """repo_dir — путь к uiuc-kang-lab/InjecAgent. variant: dh (вред) | ds (кража данных)."""
    path = Path(repo_dir) / "data" / f"test_cases_{variant}_{split}.json"
    if not path.exists():
        raise FileNotFoundError(f"нет файла InjecAgent: {path}")
    data = json.load(path.open())
    perm = P.ACTIONS
    tech = "exfiltration" if variant == "ds" else "tool_call"
    out: list[AttackSample] = []
    for it in data:
        q = it.get("User Instruction", "Use the tool and report the result.")
        injected = it.get("Tool Response", "")
        attacker = it.get("Attacker Instruction", "")
        template = it.get("Tool Response Template", "")
        out.append(AttackSample(query=q, chunk_text=injected, is_injected=True, permission=perm,
                                technique=tech, intent=intent, source=f"injecagent/{variant}",
                                meta={"attack": attacker, "injected_task": attacker,
                                      "attack_type": it.get("Attack Type")}))
        if template:  # чистый аналог: плейсхолдер → безобидный отзыв
            clean = template.replace("<Attacker Instruction>", _INJECAGENT_BENIGN_REVIEW)
            out.append(AttackSample(query=q, chunk_text=clean, is_injected=False, intent=intent,
                                    source=f"injecagent/{variant}", meta={"category": "clean"}))
        if limit and len(out) >= limit:
            break
    return out


# ---- Chen et al., ACL 2025 (Inj-SQuAD / Inj-TriviaQA — тихая подмена задачи) ------------------
# data/crafted_instruction_data_{squad,tri}_injection_qa.json:
#   instruction — вопрос пользователя; input — контекст; injection — внедряемая задача.
# В статье инъекция вставляется в начало/середину/конец контекста — повторяем все три позиции.
def _insert_at(context: str, injection: str, position: str) -> str:
    from ..text import split_sentences
    if position == "head":
        return injection + "\n" + context
    if position == "tail":
        return context.rstrip() + "\n" + injection
    sents = split_sentences(context)
    mid = max(1, len(sents) // 2)
    return " ".join(sents[:mid]) + " " + injection + " " + " ".join(sents[mid:])


def load_chen(repo_dir: str, dataset: str = "squad", limit: int | None = None,
              intent: str = "qa", positions: tuple[str, ...] = ("head", "middle", "tail")) -> list[AttackSample]:
    """repo_dir — путь к LukeChen-go/indirect-pia-detection. dataset: squad | tri."""
    path = Path(repo_dir) / "data" / f"crafted_instruction_data_{dataset}_injection_qa.json"
    if not path.exists():
        raise FileNotFoundError(f"нет файла Chen et al.: {path}")
    data = json.load(path.open())
    out: list[AttackSample] = []
    for i, it in enumerate(data):
        q = it.get("instruction", "Answer the question based on the context.")
        ctx = it.get("input", "")
        inj = (it.get("injection") or "").strip()
        if not ctx or not inj:
            continue
        pos = positions[i % len(positions)]
        out.append(AttackSample(query=q, chunk_text=_insert_at(ctx, inj, pos), is_injected=True,
                                permission=P.TASK, technique="task_swap", intent=intent,
                                source=f"chen/{dataset}",
                                meta={"injected_task": inj, "position": pos}))
        out.append(AttackSample(query=q, chunk_text=ctx, is_injected=False, intent=intent,
                                source=f"chen/{dataset}", meta={"category": "clean"}))
        if limit and len(out) >= 2 * limit:
            break
    return out


# ---- Raccoon (извлечение системного промпта — вид влияния disclosure) ------------------------
# Категории атак лежат как Data/attacks/singular_attacks/<Категория>/promptN (простой текст).
# Все нацелены на раскрытие системного промпта; отдельные категории — модификаторы.
_RACCOON_TECH = {
    "Payload Splitting": "distributed",
    "Obfuscation": "obfuscation",
    "Translation": "obfuscation",
}
# нейтральные «несущие» документы, в которые встраивается атака (имитация retrieved-фрагмента)
_RACCOON_CARRIERS = [
    "The quarterly report summarizes revenue, margins and customer growth for the period.",
    "This article explains how photosynthesis converts light energy into chemical energy in plants.",
    "The runbook describes the standard steps for handling a service outage.",
    "The travel policy covers flights, hotels and daily allowances for business trips.",
    "The knowledge base entry answers common questions about resetting a password.",
]


def load_raccoon(repo_dir: str, limit: int | None = None, intent: str = "summarize",
                 per_category: int | None = None) -> list[AttackSample]:
    """repo_dir — путь к M0gician/RaccoonBench. Атаки на раскрытие системного промпта.

    Текст атаки встраивается в нейтральный документ (как если бы он пришёл из найденного
    фрагмента); чистый аналог — тот же документ без вставки.
    """
    base = Path(repo_dir) / "Data" / "attacks" / "singular_attacks"
    if not base.is_dir():
        raise FileNotFoundError(f"нет каталога Raccoon: {base} (склонируйте M0gician/RaccoonBench)")
    out: list[AttackSample] = []
    carriers = _RACCOON_CARRIERS
    ci = 0
    for cat_dir in sorted(base.iterdir()):
        if not cat_dir.is_dir():
            continue
        cat = cat_dir.name
        tech = _RACCOON_TECH.get(cat, "disclose")
        files = sorted(cat_dir.iterdir())
        if per_category:
            files = files[:per_category]
        for f in files:
            if not f.is_file():
                continue
            try:
                attack = f.read_text(encoding="utf-8", errors="ignore").strip()
            except OSError:
                continue
            if not attack:
                continue
            carrier = carriers[ci % len(carriers)]
            ci += 1
            out.append(AttackSample(query="Briefly summarize this document.",
                                    chunk_text=carrier + "\n" + attack, is_injected=True,
                                    permission=P.DISCLOSURE, technique=tech, intent=intent,
                                    source="raccoon", meta={"category": cat, "injected_task": attack[:200]}))
            out.append(AttackSample(query="Briefly summarize this document.", chunk_text=carrier,
                                    is_injected=False, intent=intent, source="raccoon",
                                    meta={"category": "clean"}))
            if limit and len(out) >= limit:
                return out
    return out


def split_across_chunks(samples: list[AttackSample], parts: int = 2) -> list[list[AttackSample]]:
    """Преобразование: разнести инъекцию каждого примера по нескольким фрагментам одного документа.

    Моделирует распределённую инъекцию (готового бенчмарка под неё нет). Возвращает список
    «документов», каждый — несколько фрагментов с общим doc_id; несущее предложение инъекции
    разрезано на части, разложенные по фрагментам. Для оценки межфрагментного анализа.
    """
    from ..text import split_sentences
    docs: list[list[AttackSample]] = []
    for k, s in enumerate(samples):
        if not s.is_injected:
            continue
        inj = s.meta.get("injected_task") or s.meta.get("attack") or ""
        sents = split_sentences(s.chunk_text)
        # несущие предложения = те, что входят в текст инъекции
        carrier_sents = [x for x in sents if x not in inj]
        words = inj.split()
        if len(words) < parts * 2:
            continue
        step = len(words) // parts
        pieces = [" ".join(words[i * step:(i + 1) * step if i < parts - 1 else None]) for i in range(parts)]
        doc_id = f"dist:{k}"
        frags: list[AttackSample] = []
        for i, piece in enumerate(pieces):
            body = (carrier_sents[i] + " " if i < len(carrier_sents) else "") + piece
            frags.append(AttackSample(query=s.query, chunk_text=body, is_injected=True,
                                      permission=s.permission, technique="distributed", intent=s.intent,
                                      source="distributed", meta={"doc_id": doc_id, "part": i,
                                                                  "injected_task": inj}))
        docs.append(frags)
    return docs


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
