"""Правиловый скорер заявляемого влияния предложения на П2–П6.

Идея: оценивается не «вредоносность», а то, на какую часть поведения модели предложение
претендует: адресовано ли оно модели, ссылается ли на её правила/задачу/инструменты,
требует ли раскрыть данные или изменить форму/канал ответа.
Сочетание признаков — noisy-OR весов сработавших шаблонов с поправками:
  + адресация модели (AI/assistant/…) усиливает притязание;
  − цитирование / косвенная речь («например, злоумышленники пишут "…"») ослабляет его;
  − инструкции, адресованные человеку-читателю без признаков адресации модели, ослабляются.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..text import MD_IMAGE_RE, extract_urls, url_domain
from ..types import Permission as P

_F = re.I | re.U


@dataclass(frozen=True)
class Rule:
    perm: P
    pattern: re.Pattern
    weight: float
    tag: str


def R(perm: P, pattern: str, weight: float, tag: str) -> Rule:
    return Rule(perm, re.compile(pattern, _F), weight, tag)


META = r"(instructions?|rules|guidelines|directives|system prompt|prompt|programming|constraints|policies|context|указани\w*|инструкци\w*|правил\w*|ограничени\w*|системн\w+ промпт\w*)"
AI = r"(\bAI\b|\bA\.I\.|assistant|language model|\bLLM\b|chat ?bot|\bGPT\b|\bmodel\b|agent|\bbot\b|ИИ|ассистент\w*|нейросет\w*|модел\w*|бот\w*)"

RULES: tuple[Rule, ...] = (
    # ---- П3: инструкции модели -------------------------------------------------------
    R(P.P3_INSTRUCTIONS, rf"\b(ignore|disregard|forget|override|bypass|discard|skip|drop|abandon)\b.{{0,40}}\b(all|any|the|your|previous|prior|above|earlier|preceding|original)?\b.{{0,25}}{META}", 0.85, "override"),
    R(P.P3_INSTRUCTIONS, rf"\b(игнорир\w*|забудь\w*|не обращай\w* внимани\w*|отмен\w*|пренебрег\w*)\b.{{0,40}}{META}", 0.85, "override_ru"),
    R(P.P3_INSTRUCTIONS, r"\b(new|updated|real|actual|revised|additional)\s+(system\s+)?(instructions?|rules|directives|policy)\b", 0.6, "new_rules"),
    R(P.P3_INSTRUCTIONS, r"\b(нов\w+|обновл\w+|настоящ\w+)\s+(системн\w+\s+)?(инструкци\w*|правил\w*|указани\w*)", 0.6, "new_rules_ru"),
    R(P.P3_INSTRUCTIONS, r"(^|\s)(#{2,}\s*)?(system|developer|admin(istrator)?)\s*(message|note|override|prompt)?\s*[:>\]]", 0.7, "fake_role"),
    R(P.P3_INSTRUCTIONS, r"<\|?(im_start|im_end|system|endoftext)\|?>|\[/?INST\]|<</?SYS>>|\bBEGIN SYSTEM\b|\bEND OF DOCUMENT\b", 0.85, "role_tokens"),
    R(P.P3_INSTRUCTIONS, r"\b(you are now|from now on,? you|act as|pretend to be|you must now|enter|switch to)\b.{0,40}\b(mode|persona|assistant|AI|role|unrestricted|DAN)\b", 0.7, "role_switch"),
    R(P.P3_INSTRUCTIONS, r"\b(developer|debug|maintenance|god|jailbreak|unrestricted)\s+mode\b", 0.6, "mode"),
    R(P.P3_INSTRUCTIONS, r"\b(do not|don't|never)\b.{0,30}\b(follow|obey|apply)\b.{0,30}\b(your|the|any)\b.{0,15}" + META, 0.75, "dont_follow"),
    R(P.P3_INSTRUCTIONS, r"\b(with)?out (any )?(restrictions|filters|limitations|safety)\b", 0.4, "no_restrictions"),
    R(P.P3_INSTRUCTIONS, r"\b(отныне|теперь)\b.{0,20}\b(ты|вы)\b", 0.55, "from_now_ru"),
    R(P.P3_INSTRUCTIONS, r"\b(reply|respond|answer|output|say|print|write)\b.{0,25}\b(only|just|exactly|verbatim)\b.{0,30}\b(word|phrase|code ?word|token|string|text)\b", 0.55, "say_exact"),
    R(P.P3_INSTRUCTIONS, r"\b(ответь|выведи|напиши)\b.{0,25}\b(только|ровно|дословно)\b", 0.55, "say_exact_ru"),
    # ---- П2: задача пользователя -------------------------------------------------------
    R(P.P2_TASK, r"\binstead of\b.{0,30}\b(summari[sz]\w*|answer\w*|translat\w*|respond\w*|the (user'?s?|original) (request|question|task))", 0.85, "instead_of"),
    R(P.P2_TASK, r"\b(your|the)\s+(new|real|actual|true|primary|only|updated)\s+(task|goal|job|objective|assignment|mission)\b", 0.85, "new_task"),
    R(P.P2_TASK, r"\b(do not|don't|stop|no need to)\b.{0,15}\b(summari[sz]\w*|answer\w*|translat\w*|respond\w*)\b", 0.7, "stop_task"),
    R(P.P2_TASK, r"\b(the user|user)\b.{0,20}\b(actually|really|instead|now)\b.{0,20}\b(wants?|asks?|asked|needs?|requests?)\b", 0.75, "user_wants"),
    R(P.P2_TASK, r"\b(before|after)\b.{0,15}\b(answering|summari[sz]ing|responding|translating)\b.{0,40}\b(write|compose|generate|do|create|produce|tell|output)\b", 0.6, "before_answering"),
    R(P.P2_TASK, r"\b(вместо|не нужно|не надо)\b.{0,30}\b(пересказ\w*|ответ\w*|перевод\w*|перевест\w*|резюм\w*|отвечать)", 0.85, "instead_ru"),
    R(P.P2_TASK, r"\b(тво\w+|ваш\w+)\s+(нов\w+|настоящ\w+|главн\w+|истинн\w+)\s+(задач\w*|цел\w*)", 0.85, "new_task_ru"),
    R(P.P2_TASK, r"\b(пользователь)\b.{0,25}\b(на самом деле|хочет|просит)\b", 0.6, "user_wants_ru"),
    R(P.P2_TASK, r"\b(write|compose|generate)\b.{0,20}\b(a |an )?(poem|story|joke|essay|song|limerick)\b", 0.4, "offtopic_gen"),
    # ---- П4: раскрытие информации --------------------------------------------------------
    R(P.P4_DISCLOSURE, r"\b(reveal|print|output|show|repeat|recite|tell|disclose|leak|display|share|dump|list|include|paste|return)\b.{0,40}\b(system prompt|your (instructions|prompt|rules|configuration|config)|(initial|hidden|secret|original) (instructions|prompt)|configuration id|config id|api[ _-]?keys?|passwords?|credentials|secrets?|access tokens?|conversation history|chat history|previous messages|other users?'?s?|private (data|documents|records)|internal (data|documents|notes|config\w*)|database contents)\b", 0.85, "reveal"),
    R(P.P4_DISCLOSURE, r"\b(what (are|were) your (instructions|rules)|everything above|text above this line|words above)\b", 0.7, "what_instructions"),
    R(P.P4_DISCLOSURE, r"\b(раскрой|выведи|покажи|повтори|сообщи|перечисли|вставь)\w*\b.{0,40}\b(системн\w+ промпт\w*|сво\w+ (инструкц|правил|настройк)\w*|конфигурац\w*|парол\w*|ключ\w*|секрет\w*|истори\w+ (переписк|диалог)\w*|друг\w+ пользовател\w*|персональн\w+ данн\w*)", 0.85, "reveal_ru"),
    R(P.P4_DISCLOSURE, r"\b(contents? of|all records|entire|full)\b.{0,20}\b(the )?(database|customer table|user table|crm|mailbox)\b", 0.6, "dump_data"),
    # ---- П5: действия / инструменты ------------------------------------------------------
    R(P.P5_ACTIONS, r"\b(call|invoke|use|run|execute|trigger|fire|perform)\b.{0,25}\b(the )?(tool|function|api|command|action|plugin)\b", 0.75, "call_tool"),
    R(P.P5_ACTIONS, r"\bCALL\s+[a-z_]+\b|\b[a-z]+_[a-z_]+\s*\(", 0.6, "tool_syntax"),
    R(P.P5_ACTIONS, r"\b(send|forward|e-?mail|mail)\b.{0,40}\b(to|at)\b.{0,10}[\w.+-]+@[\w-]+\.[\w.]+", 0.45, "send_mail_addr"),
    R(P.P5_ACTIONS, r"\b(delete|drop|wipe|erase|remove|purge|truncate)\b.{0,20}\b(all|the|every)?\b.{0,10}\b(records?|tables?|files?|database|accounts?|users?|logs?)\b", 0.5, "destructive"),
    R(P.P5_ACTIONS, r"\b(export|upload|transfer|exfiltrate|copy|sync|post)\b.{0,30}\b(database|data|records|files|table|documents?)\b.{0,30}\b(to|into)\b", 0.5, "export"),
    R(P.P5_ACTIONS, r"\b(make|send|perform|issue)\b.{0,10}\b(an? )?(http|https|get|post|web)\s*(request|call)\b", 0.6, "http"),
    R(P.P5_ACTIONS, r"\b(вызови|вызовите|запусти|выполни|используй)\w*\b.{0,25}\b(инструмент|функци|команд|api)\w*", 0.75, "call_tool_ru"),
    R(P.P5_ACTIONS, r"\b(отправь|перешли|удали|выгрузи|экспортируй)\w*\b.{0,40}\b(письм|почт|запис|баз|таблиц|файл|данн)\w*", 0.55, "action_ru"),
    # ---- П6: форма ответа и внешний канал ------------------------------------------------
    R(P.P6_FORMAT_CHANNEL, r"\b(always|must|should)?\s*(start|begin|end|finish|conclude|close|sign)\b.{0,20}\b(your|the|each|every)\b.{0,10}\b(answer|response|reply|output|message|summary)\b.{0,15}\b(with|by)\b", 0.75, "start_end_with"),
    R(P.P6_FORMAT_CHANNEL, r"\b(respond|reply|answer|write)\b.{0,20}\b(only|exclusively|entirely)\b.{0,10}\bin\b.{0,20}\b(capital|caps|uppercase|french|german|spanish|chinese|emoji|rhymes?|json|base64|pirate)\b", 0.7, "respond_only_in"),
    R(P.P6_FORMAT_CHANNEL, r"\b(include|insert|add|append|embed|attach|place|put)\b.{0,30}\b(this|the following|the|a)\b.{0,15}\b(link|url|image|picture|banner|advert\w*|promo\w*|coupon|disclaimer|slogan|signature|tracking pixel)\b", 0.7, "insert_content"),
    R(P.P6_FORMAT_CHANNEL, r"\b(tell|inform|advise|urge|recommend)\b.{0,15}\b(the )?(user|reader|customer)s?\b.{0,30}\b(to )?(visit|click|log ?in|download|call|go to|enter)\b", 0.75, "steer_user"),
    R(P.P6_FORMAT_CHANNEL, r"\b(do not|don't|never)\b.{0,10}\b(mention|tell|reveal to|inform)\b.{0,20}\b(the )?(user|reader)\b", 0.7, "hide_from_user"),
    R(P.P6_FORMAT_CHANNEL, r"\b(начни|заверши|закончи|добавь|вставь|включи)\w*\b.{0,30}\b(ответ\w*|ссылк\w*|изображени\w*|реклам\w*|подпис\w*)", 0.7, "format_ru"),
    R(P.P6_FORMAT_CHANNEL, r"\b(скажи|сообщи|посоветуй)\w*\b.{0,15}\bпользовател\w*\b.{0,30}\b(перейти|зайти|скачать|ввести)", 0.75, "steer_user_ru"),
)

ADDRESSING = re.compile(
    rf"\b(dear|attention|note (to|for)|hey|hi|hello|important|instruction for)\b.{{0,15}}{AI}"
    rf"|{AI}.{{0,20}}\b(reading|processing|summari[sz]ing|parsing|that reads|who reads|must|should|will|are|is required)\b"
    rf"|\b(if you are an?|as an?)\s+{AI}"
    rf"|\b(you are|you're)\b.{{0,15}}\b(an?\s+)?{AI}"
    r"|\b(вниманию|для|уважаем\w*)\s+(ИИ|ассистент\w*|модел\w*|нейросет\w*)",
    _F,
)
QUOTE_CONTEXT = re.compile(
    r"\b(for example|e\.g\.|such as|for instance|like|attackers?|adversar\w*|malicious|an injection|injected|payloads?|phrases? like|strings? like|"
    r"researchers?|was (found|observed)|typical|known as|например|злоумышленник\w*|атакующ\w*|такие как|вроде)\b",
    _F,
)
QUOTED = re.compile(r"[\"“«'‘].{8,}[\"”»'’]")
# Инструкции читателю-человеку («нажмите кнопку», «отправьте форму») — типичный источник ЛС.
HUMAN_READER = re.compile(
    r"\b(employees?|staff|customers?|applicants?|students?|visitors?|users? should|readers?|you can|please contact|"
    r"сотрудник\w*|клиент\w*|заявител\w*|студент\w*|пользователям следует)\b",
    _F,
)
DATA_URL = re.compile(r"[?&](q|d|data|payload|info|c|s|msg|text|content|secret|key|session)=|\{[^}]+\}|%7B|\b(USER|SECRET|DATA)\b", re.I)


@dataclass
class RuleHit:
    perm: P
    tag: str
    weight: float


class RuleScorer:
    """Возвращает для предложения оценки по П2–П6 в [0, 1] и сработавшие правила."""

    def __init__(self, rules: tuple[Rule, ...] = RULES, addressing_boost: float = 0.25,
                 quote_damp: float = 0.35, human_damp: float = 0.6):
        self.rules = rules
        self.addressing_boost = addressing_boost
        self.quote_damp = quote_damp
        self.human_damp = human_damp

    def score(self, sentence: str) -> tuple[dict[P, float], list[RuleHit], list[str]]:
        hits = [RuleHit(r.perm, r.tag, r.weight) for r in self.rules if r.pattern.search(sentence)]
        flags: list[str] = []
        # Внешний канал: ссылки/изображения
        urls = extract_urls(sentence)
        if MD_IMAGE_RE.search(sentence):
            hits.append(RuleHit(P.P6_FORMAT_CHANNEL, "md_image", 0.55))
        if any(DATA_URL.search(u) for u in urls):
            hits.append(RuleHit(P.P6_FORMAT_CHANNEL, "data_url", 0.6))
            hits.append(RuleHit(P.P4_DISCLOSURE, "data_url", 0.4))
        scores: dict[P, float] = {}
        for h in hits:
            prev = scores.get(h.perm, 0.0)
            scores[h.perm] = 1 - (1 - prev) * (1 - h.weight)
        addressed = bool(ADDRESSING.search(sentence))
        if addressed:
            flags.append("addressed_to_model")
            for p in list(scores):
                scores[p] = min(1.0, scores[p] + self.addressing_boost)
            scores[P.P3_INSTRUCTIONS] = max(scores.get(P.P3_INSTRUCTIONS, 0.0), 0.3)
        if QUOTED.search(sentence) and QUOTE_CONTEXT.search(sentence):
            flags.append("quoted_reported")
            scores = {p: v * self.quote_damp for p, v in scores.items()}
        elif not addressed and HUMAN_READER.search(sentence):
            flags.append("human_reader")
            scores = {p: v * self.human_damp for p, v in scores.items()}
        return scores, hits, flags


def mentioned_urls(sentence: str) -> list[str]:
    return extract_urls(sentence)


def mentioned_domains(sentence: str) -> list[str]:
    return [url_domain(u) for u in extract_urls(sentence)]
