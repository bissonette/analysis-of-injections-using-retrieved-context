"""Справочники: связь «техника инъекции → навязываемый вид влияния» и список модулей проекта.

Таблица техник используется как основа для разметки примеров: каждая техника пытается
навязать модели определённый вид влияния (task / instructions / disclosure / actions / format).
Модификаторы (obfuscation, distributed) не нацелены на конкретный вид влияния, а усложняют
обнаружение базовой техники.
"""
from __future__ import annotations

from .types import Permission as P
from .types import Technique as T

# Вид(ы) влияния, который пытается навязать каждая техника.
TECHNIQUE_TARGETS: dict[T, tuple[P, ...]] = {
    T.OVERRIDE: (P.INSTRUCTIONS,),
    T.TASK_SWAP: (P.TASK,),
    T.FAKE_SYSTEM: (P.INSTRUCTIONS,),
    T.DISCLOSE: (P.DISCLOSURE,),
    T.TOOL_CALL: (P.ACTIONS,),
    T.EXFILTRATION: (P.FORMAT, P.DISCLOSURE),
    T.CONTENT_INSERT: (P.FORMAT,),
    T.FALSE_AUTHORITY: (P.TASK, P.ACTIONS),
    T.OBFUSCATION: (),   # модификатор — наследует цель базовой техники
    T.DISTRIBUTED: (),   # модификатор
}

MODIFIERS = (T.OBFUSCATION, T.DISTRIBUTED)
BASE_TECHNIQUES = tuple(t for t in T if t not in MODIFIERS)

# Модули проекта (для навигации по коду).
MODULES: dict[str, str] = {
    "Веб-интерфейс": "ctxauth.ui (не реализован)",
    "Оркестратор стенда": "ctxauth.rag.orchestrator",
    "Системный промпт": "ctxauth.rag.prompts",
    "Загрузка и разметка данных": "ctxauth.data.loaders",
    "Разбиение на фрагменты / эмбеддинг": "ctxauth.rag.chunking, ctxauth.rag.embed",
    "Векторное хранилище": "ctxauth.rag.index",
    "Поиск (ретривер)": "ctxauth.rag.retriever",
    "Контроль разрешений контекста (основной метод)": "ctxauth.authority",
    "LLM (локальный инференс)": "ctxauth.rag.llm",
    "Регистратор действий (инструменты)": "ctxauth.rag.tools",
    "Постобработка ответа": "ctxauth.rag.postprocess",
    "Журналирование": "ctxauth.rag.audit",
    "Командная строка": "ctxauth.cli",
    "Оценка и метрики": "ctxauth.eval",
}


def targets_of(techniques: list[T] | tuple[T, ...]) -> set[P]:
    out: set[P] = set()
    for t in techniques:
        out.update(TECHNIQUE_TARGETS.get(t, ()))
    return out
