"""Определение делегированного профиля по запросу пользователя: запрос → RequestPolicy.

Это реализация ключевой договорённости «профиль полномочий зависит от запроса пользователя»
(УБИ-С14). Запрос классифицируется в одно из намерений, каждому намерению соответствует
набор полномочий, которые пользователь делегирует retrieved-контексту.
П3 (инструкции модели) и П4 (раскрытие информации) контексту не делегируются никогда.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..types import Permission as P
from ..types import RequestPolicy


@dataclass(frozen=True)
class IntentSpec:
    name: str
    allowed: frozenset[P]
    tool_scope: frozenset[str] = frozenset()
    patterns: tuple[str, ...] = ()
    description: str = ""


INTENTS: tuple[IntentSpec, ...] = (
    IntentSpec(
        "follow_procedure",
        frozenset({P.P2_TASK, P.P5_ACTIONS}),
        frozenset({"create_ticket", "search_kb"}),
        (
            r"\b(follow|execute|carry out|perform|run|apply|complete)\b.{0,40}\b(steps|instructions|procedure|runbook|checklist|playbook|ticket)\b",
            r"\bdo what\b.{0,30}\b(document|ticket|runbook|page)\b.{0,10}\b(says|asks|requires)\b",
            r"\b(выполни|выполните|проделай|исполни)\w*\b.{0,40}\b(шаг|инструкц|процедур|регламент|заявк|чек-?лист)",
        ),
        "Пользователь явно поручает выполнить процедуру из документа (агентный сценарий).",
    ),
    IntentSpec(
        "format_by_doc",
        frozenset({P.P6_FORMAT_CHANNEL}),
        frozenset(),
        (
            r"\b(format|style|structure|lay ?out|write)\b.{0,40}\b(according to|following|per|as (in|described in)|using)\b.{0,30}\b(template|style ?guide|guidelines|document|example)\b",
            r"\b(оформи|оформите|отформатируй|составь)\w*\b.{0,40}\b(по|согласно)\b.{0,20}\b(шаблон|образц|требовани|документ)",
        ),
        "Пользователь просит оформить ответ по правилам из документа: форма ответа делегирована.",
    ),
    IntentSpec("translate", frozenset(), frozenset(), (r"\btranslat\w*\b", r"\bпереве\w*\b")),
    IntentSpec(
        "summarize", frozenset(), frozenset(),
        (r"\b(summari[sz]\w*|summary|brief(ly)?|tl;?dr|overview|recap|gist)\b",
         r"\b(кратко|перескаж\w*|резюм\w*|суммариз\w*|основн\w+ мысл\w*)\b"),
    ),
    IntentSpec(
        "extract_steps", frozenset(), frozenset(),
        (r"\b(what|which|list)\b.{0,30}\b(steps|instructions|recommendations|actions)\b",
         r"\bwhat does\b.{0,40}\b(say|tell|recommend|ask)\b",
         r"\b(какие|перечисли)\b.{0,30}\b(шаг|инструкц|рекомендац|действи)"),
    ),
    IntentSpec("compare", frozenset(), frozenset(), (r"\b(compare|difference|versus|vs\.?)\b", r"\b(сравни|отлича)\w*")),
    IntentSpec("qa", frozenset(), frozenset(), ()),
)

INTENT_BY_NAME = {i.name: i for i in INTENTS}
# Домены, ссылки на которые допустимы в ответе (организационная мера; задаётся администратором К13).
DEFAULT_DOMAIN_ALLOWLIST = frozenset({"intranet.local", "docs.company.local", "kb.company.local"})


class IntentRecognizer:
    def __init__(self, intents: tuple[IntentSpec, ...] = INTENTS,
                 domain_allowlist: frozenset[str] = DEFAULT_DOMAIN_ALLOWLIST):
        self.intents = intents
        self.compiled = [(i, [re.compile(p, re.I) for p in i.patterns]) for i in intents]
        self.domain_allowlist = domain_allowlist

    def recognize(self, query: str) -> str:
        for spec, pats in self.compiled:
            if any(p.search(query) for p in pats):
                return spec.name
        return "qa"

    def policy(self, query: str, intent: str | None = None) -> RequestPolicy:
        spec = INTENT_BY_NAME[intent or self.recognize(query)]
        return RequestPolicy(spec.name, spec.allowed, spec.tool_scope, self.domain_allowlist)


def static_policy(domain_allowlist: frozenset[str] = DEFAULT_DOMAIN_ALLOWLIST) -> RequestPolicy:
    """Профиль, не зависящий от запроса (для абляции: «статический» вариант метода)."""
    return RequestPolicy("static", frozenset(), frozenset(), domain_allowlist)
