"""Базовые типы предметной области: полномочия П1–П6, техники ТК1–ТК10,
фрагменты контекста, профили полномочий и решения модуля К8.

Обозначения совпадают с моделью угроз (раздел 6.4 THESIS_CONTEXT):
П1 — содержание ответа, П2 — задача пользователя, П3 — инструкции модели,
П4 — раскрытие информации, П5 — действия/инструменты, П6 — форма ответа и внешний канал.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Permission(IntEnum):
    """Классы полномочий фрагмента retrieved-контекста."""

    P1_CONTENT = 1  # влияние на фактическое содержание ответа (разрешено по умолчанию)
    P2_TASK = 2  # изменение задачи пользователя
    P3_INSTRUCTIONS = 3  # инструкции модели: системный промпт, правила обработки
    P4_DISCLOSURE = 4  # раскрытие информации (системный промпт, чужие данные, секреты)
    P5_ACTIONS = 5  # действия / вызовы инструментов
    P6_FORMAT_CHANNEL = 6  # форма ответа и внешний канал (серая зона)

    @property
    def code(self) -> str:
        return f"P{int(self)}"

    @property
    def title_ru(self) -> str:
        return PERMISSION_TITLES_RU[self]

    @classmethod
    def from_code(cls, code: str) -> "Permission":
        code = code.strip().upper().replace("П", "P")
        return cls(int(code.lstrip("P")))


PERMISSION_TITLES_RU = {
    Permission.P1_CONTENT: "Влияние на содержание ответа",
    Permission.P2_TASK: "Изменение задачи пользователя",
    Permission.P3_INSTRUCTIONS: "Инструкции модели",
    Permission.P4_DISCLOSURE: "Раскрытие информации",
    Permission.P5_ACTIONS: "Действия / вызовы инструментов",
    Permission.P6_FORMAT_CHANNEL: "Форма ответа и внешний канал",
}

# Полномочия, которые проверяются (П1 разрешено всегда и не «заявляется» как нарушение).
CONTROLLED = (
    Permission.P2_TASK,
    Permission.P3_INSTRUCTIONS,
    Permission.P4_DISCLOSURE,
    Permission.P5_ACTIONS,
    Permission.P6_FORMAT_CHANNEL,
)


class Technique(str, Enum):
    """Классы техник косвенного воздействия ТК1–ТК10 (основа разметки датасета)."""

    TK1 = "TK1"  # прямое переопределение указаний («ignore previous instructions»)
    TK2 = "TK2"  # подмена задачи пользователя
    TK3 = "TK3"  # имитация системного / служебного сообщения, ролевой разметки
    TK4 = "TK4"  # запрос раскрытия системного промпта, секретов, чужих данных
    TK5 = "TK5"  # инициирование действий / вызовов инструментов
    TK6 = "TK6"  # эксфильтрация через внешний канал (ссылки, изображения)
    TK7 = "TK7"  # навязывание формы ответа, вставка контента (реклама, фишинг)
    TK8 = "TK8"  # ссылка на мнимые полномочия («пользователь разрешил…»), злоупотребление доверием
    TK9 = "TK9"  # модификатор: снижение заметности (обфускация, скрытый текст)
    TK10 = "TK10"  # модификатор: распределение воздействия по нескольким чанкам


TECHNIQUE_TITLES_RU = {
    Technique.TK1: "Переопределение указаний",
    Technique.TK2: "Подмена задачи",
    Technique.TK3: "Имитация служебного сообщения",
    Technique.TK4: "Запрос раскрытия информации",
    Technique.TK5: "Инициирование действий",
    Technique.TK6: "Эксфильтрация через внешний канал",
    Technique.TK7: "Навязывание формы ответа / вставка контента",
    Technique.TK8: "Ссылка на мнимые полномочия",
    Technique.TK9: "Снижение заметности (модификатор)",
    Technique.TK10: "Распределение по чанкам (модификатор)",
}


class Action(str, Enum):
    """Решение модуля К8 относительно фрагмента."""

    PASS = "pass"  # фрагмент передаётся в LLM без изменений
    SANITIZE = "sanitize"  # из фрагмента удалены предложения, превышающие полномочия
    BLOCK = "block"  # фрагмент целиком исключён из контекста


@dataclass
class Chunk:
    """Фрагмент retrieved-контекста (выход К7)."""

    chunk_id: str
    doc_id: str
    text: str
    position: int = 0  # порядковый номер чанка внутри документа
    score: float = 0.0  # релевантность по ретриверу
    meta: dict[str, Any] = field(default_factory=dict)


@dataclass
class ToolSpec:
    name: str
    description: str
    external: bool = False  # инструмент выводит данные за пределы стенда


@dataclass
class RequestPolicy:
    """Делегированный запросом пользователя профиль: что контексту разрешено менять.

    Профиль зависит от запроса (УБИ-С14): один и тот же фрагмент может быть
    легитимен для одного запроса и недопустим для другого.
    """

    intent: str
    allowed: frozenset[Permission]
    tool_scope: frozenset[str] = frozenset()  # инструменты, которые контекст может инициировать
    domain_allowlist: frozenset[str] = frozenset()  # домены, на которые допустимы ссылки

    def allows(self, p: Permission) -> bool:
        return p == Permission.P1_CONTENT or p in self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "allowed": sorted(p.code for p in self.allowed | {Permission.P1_CONTENT}),
            "tool_scope": sorted(self.tool_scope),
            "domain_allowlist": sorted(self.domain_allowlist),
        }


@dataclass
class SentenceEvidence:
    """Оценка заявляемого влияния для одного предложения фрагмента."""

    text: str
    scores: dict[Permission, float]
    tools: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    flags: list[str] = field(default_factory=list)  # например hidden_text, base64, quoted

    def max_controlled(self) -> tuple[Permission | None, float]:
        best, val = None, 0.0
        for p in CONTROLLED:
            s = self.scores.get(p, 0.0)
            if s > val:
                best, val = p, s
        return best, val


@dataclass
class Violation:
    permission: Permission
    score: float
    reason: str
    sentence: str


@dataclass
class AuthorityProfile:
    """Профиль заявляемого влияния фрагмента (вектор по П2–П6) + доказательства."""

    claimed: dict[Permission, float]
    sentences: list[SentenceEvidence]

    def as_codes(self) -> dict[str, float]:
        return {p.code: round(v, 3) for p, v in self.claimed.items()}


@dataclass
class ChunkDecision:
    chunk: Chunk
    action: Action
    profile: AuthorityProfile
    violations: list[Violation]
    sanitized_text: str | None = None

    @property
    def passed_text(self) -> str | None:
        if self.action == Action.PASS:
            return self.chunk.text
        if self.action == Action.SANITIZE:
            return self.sanitized_text
        return None


@dataclass
class FilterResult:
    """Результат работы фильтра над набором фрагментов для одного запроса."""

    policy: RequestPolicy | None
    decisions: list[ChunkDecision]
    latency_ms: float = 0.0

    @property
    def kept_chunks(self) -> list[Chunk]:
        out = []
        for d in self.decisions:
            t = d.passed_text
            if t:
                out.append(Chunk(d.chunk.chunk_id, d.chunk.doc_id, t, d.chunk.position, d.chunk.score, d.chunk.meta))
        return out
