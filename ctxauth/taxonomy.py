"""Справочники модели угроз, используемые в коде: связь ТК ↔ П, УБИ-С ↔ П,
компоненты стенда К1–К14 ↔ модули реализации.

Эти таблицы — «мост» между текстом модели угроз (раздел 1 ВКР) и экспериментами:
по ним размечается датасет и строятся разрезы метрик.
"""
from __future__ import annotations

from .types import Permission as P
from .types import Technique as TK

# Основное (и дополнительные) полномочие, которое пытается нарушить техника.
TECHNIQUE_TARGETS: dict[TK, tuple[P, ...]] = {
    TK.TK1: (P.P3_INSTRUCTIONS,),
    TK.TK2: (P.P2_TASK,),
    TK.TK3: (P.P3_INSTRUCTIONS,),
    TK.TK4: (P.P4_DISCLOSURE,),
    TK.TK5: (P.P5_ACTIONS,),
    TK.TK6: (P.P6_FORMAT_CHANNEL, P.P4_DISCLOSURE),
    TK.TK7: (P.P6_FORMAT_CHANNEL,),
    TK.TK8: (P.P2_TASK, P.P5_ACTIONS),
    TK.TK9: (),  # модификатор — наследует цели базовой техники
    TK.TK10: (),  # модификатор
}

MODIFIERS = (TK.TK9, TK.TK10)
BASE_TECHNIQUES = tuple(t for t in TK if t not in MODIFIERS)

# Угрозы УБИ-С, входящие в область действия метода, и полномочия, через которые они реализуются.
# ВНИМАНИЕ: в THESIS_CONTEXT зафиксирован только состав (С1–С7, С14 — в области метода),
# но не формулировки каждой угрозы. Соответствие ниже — рабочее, сверить с таблицей УБИ-С
# в тексте модели угроз и при необходимости поправить (используется только для отчётов).
THREATS_IN_SCOPE: dict[str, tuple[P, ...]] = {
    "УБИ-С1": (P.P3_INSTRUCTIONS,),
    "УБИ-С2": (P.P2_TASK,),
    "УБИ-С3": (P.P4_DISCLOSURE,),
    "УБИ-С4": (P.P5_ACTIONS,),
    "УБИ-С5": (P.P6_FORMAT_CHANNEL,),
    "УБИ-С6": (P.P4_DISCLOSURE, P.P6_FORMAT_CHANNEL),
    "УБИ-С7": (P.P3_INSTRUCTIONS, P.P2_TASK),
    "УБИ-С14": (P.P2_TASK, P.P5_ACTIONS, P.P6_FORMAT_CHANNEL),
}
# Вне области действия метода (см. модель угроз): С8 — искажение фактов (П1),
# С9 — прямой запрос сверх прав, С11–С13 — общесистемные меры.
THREATS_OUT_OF_SCOPE = ("УБИ-С8", "УБИ-С9", "УБИ-С11", "УБИ-С12", "УБИ-С13")
# УБИ-С10 (непреднамеренный источник) — используется для оценки ложных срабатываний.
THREAT_FALSE_POSITIVE_PROBE = "УБИ-С10"

# Компоненты стенда К1–К14 → модули реализации.
COMPONENTS: dict[str, tuple[str, str]] = {
    "К1": ("Веб-интерфейс", "ctxauth.ui.server"),
    "К2": ("Оркестратор", "ctxauth.rag.orchestrator"),
    "К3": ("Системный промпт", "ctxauth.rag.prompts"),
    "К4": ("Коннекторы загрузки и индексации", "ctxauth.data.loaders"),
    "К5": ("Предобработка / чанкинг / эмбеддинг", "ctxauth.rag.chunking, ctxauth.rag.embed"),
    "К6": ("Векторная БД", "ctxauth.rag.index"),
    "К7": ("Ретривер + реранкер", "ctxauth.rag.retriever"),
    "К8": ("Точка контроля полномочий контекста", "ctxauth.authority"),
    "К9": ("LLM (локальный инференс)", "ctxauth.rag.llm"),
    "К10": ("Инструмент-регистратор действий", "ctxauth.rag.tools"),
    "К11": ("Постобработка / рендеринг", "ctxauth.rag.postprocess"),
    "К12": ("Журналирование", "ctxauth.rag.audit"),
    "К13": ("Средства администрирования", "ctxauth.cli"),
    "К14": ("Хранилище документов / конфигурации", "ctxauth.data, configs/"),
}


def targets_of(techniques: list[TK] | tuple[TK, ...]) -> set[P]:
    out: set[P] = set()
    for t in techniques:
        out.update(TECHNIQUE_TARGETS.get(t, ()))
    return out
