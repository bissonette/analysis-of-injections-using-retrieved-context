"""Базовые типы: виды влияния фрагмента на ответ модели, техники инъекций,
фрагменты контекста, разрешения запроса и решения фильтра.

Виды влияния, которые retrieved-фрагмент может оказывать на поведение модели:
  content      — влияние на содержание ответа (разрешено по умолчанию);
  task         — изменение задачи, которую решает модель;
  instructions — изменение правил/инструкций модели (системный промпт, роль);
  disclosure   — раскрытие служебной или чужой информации, секретов;
  actions      — инициирование действий и вызовов инструментов;
  format       — навязывание формы ответа и вывод во внешний канал (ссылки, изображения).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum, IntEnum
from typing import Any


class Permission(IntEnum):
    """Вид влияния, которое фрагмент контекста может оказывать на ответ модели."""

    CONTENT = 1  # влияние на фактическое содержание ответа (разрешено по умолчанию)
    TASK = 2  # изменение задачи пользователя
    INSTRUCTIONS = 3  # правила/инструкции модели: системный промпт, роль, правила обработки
    DISCLOSURE = 4  # раскрытие информации (системный промпт, чужие данные, секреты)
    ACTIONS = 5  # действия / вызовы инструментов
    FORMAT = 6  # форма ответа и внешний канал

    @property
    def code(self) -> str:
        return self.name.lower()

    @property
    def title_ru(self) -> str:
        return PERMISSION_TITLES_RU[self]

    @classmethod
    def from_code(cls, code: str) -> "Permission":
        return cls[code.strip().upper()]


PERMISSION_TITLES_RU = {
    Permission.CONTENT: "Влияние на содержание ответа",
    Permission.TASK: "Изменение задачи пользователя",
    Permission.INSTRUCTIONS: "Изменение инструкций модели",
    Permission.DISCLOSURE: "Раскрытие информации",
    Permission.ACTIONS: "Действия / вызовы инструментов",
    Permission.FORMAT: "Форма ответа и внешний канал",
}

# Виды влияния, которые проверяются (content разрешён всегда и не считается нарушением).
CONTROLLED = (
    Permission.TASK,
    Permission.INSTRUCTIONS,
    Permission.DISCLOSURE,
    Permission.ACTIONS,
    Permission.FORMAT,
)


class Technique(str, Enum):
    """Техники косвенных инъекций (используются для разметки примеров)."""

    OVERRIDE = "override"  # прямое переопределение указаний («ignore previous instructions»)
    TASK_SWAP = "task_swap"  # подмена задачи пользователя
    FAKE_SYSTEM = "fake_system"  # имитация системного / служебного сообщения, ролевой разметки
    DISCLOSE = "disclose"  # запрос раскрытия системного промпта, секретов, чужих данных
    TOOL_CALL = "tool_call"  # инициирование действий / вызовов инструментов
    EXFILTRATION = "exfiltration"  # вывод данных через внешний канал (ссылки, изображения)
    CONTENT_INSERT = "content_insert"  # навязывание формы ответа, вставка контента (реклама, фишинг)
    FALSE_AUTHORITY = "false_authority"  # ссылка на мнимые полномочия («пользователь разрешил…»)
    OBFUSCATION = "obfuscation"  # модификатор: снижение заметности (обфускация, скрытый текст)
    DISTRIBUTED = "distributed"  # модификатор: распределение воздействия по нескольким фрагментам


TECHNIQUE_TITLES_RU = {
    Technique.OVERRIDE: "Переопределение указаний",
    Technique.TASK_SWAP: "Подмена задачи",
    Technique.FAKE_SYSTEM: "Имитация служебного сообщения",
    Technique.DISCLOSE: "Запрос раскрытия информации",
    Technique.TOOL_CALL: "Инициирование действий",
    Technique.EXFILTRATION: "Вывод через внешний канал",
    Technique.CONTENT_INSERT: "Навязывание формы ответа / вставка контента",
    Technique.FALSE_AUTHORITY: "Ссылка на мнимые полномочия",
    Technique.OBFUSCATION: "Снижение заметности (модификатор)",
    Technique.DISTRIBUTED: "Распределение по фрагментам (модификатор)",
}


class Action(str, Enum):
    """Решение фильтра по фрагменту."""

    PASS = "pass"  # фрагмент передаётся в LLM без изменений
    SANITIZE = "sanitize"  # из фрагмента удалены предложения, превышающие разрешения
    BLOCK = "block"  # фрагмент целиком исключён из контекста


@dataclass
class Chunk:
    """Фрагмент retrieved-контекста (результат поиска)."""

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
    external: bool = False  # инструмент выводит данные во внешний мир


@dataclass
class RequestPolicy:
    """Что запрос пользователя разрешает контексту менять в поведении модели.

    Набор разрешений зависит от запроса: один и тот же фрагмент может быть
    легитимен для одного запроса и недопустим для другого.
    """

    intent: str
    allowed: frozenset[Permission]
    tool_scope: frozenset[str] = frozenset()  # инструменты, которые контекст может инициировать
    domain_allowlist: frozenset[str] = frozenset()  # домены, на которые допустимы ссылки

    def allows(self, p: Permission) -> bool:
        return p == Permission.CONTENT or p in self.allowed

    def to_dict(self) -> dict[str, Any]:
        return {
            "intent": self.intent,
            "allowed": sorted(p.code for p in self.allowed | {Permission.CONTENT}),
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
    """Профиль заявляемого влияния фрагмента (по видам влияния) + доказательства."""

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
