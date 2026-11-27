"""Контроль разрешений retrieved-контекста — основной метод.

Для каждого retrieved-фрагмента до передачи в LLM:
  1) по запросу пользователя определяется, что фрагменту разрешено менять (RequestPolicy);
  2) оценивается, на какие виды влияния претендует фрагмент (AuthorityProfile);
  3) находятся нарушения: заявлен вид влияния, не разрешённый запросом, либо разрешённый,
     но выходящий за рамки (инструмент вне tool_scope, ссылка вне allowlist);
  4) принимается решение PASS / SANITIZE / BLOCK — без вердикта «атака/не атака».
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..text import domain_allowed, normalize, sentence_spans, url_domain
from ..tools_meta import EXTERNAL_TOOLS
from ..types import (CONTROLLED, Action, AuthorityProfile, Chunk, ChunkDecision, FilterResult,
                     RequestPolicy, SentenceEvidence, Violation)
from ..types import Permission as P
from .analyzer import AuthorityAnalyzer
from .intent import IntentRecognizer, static_policy

REMOVED_MARK = "[removed by context authority control]"
# Ссылки на «отложенные» части инъекции, разнесённой по нескольким фрагментам.
DEFERRED_REF = re.compile(
    r"\b(remember|keep in mind|memori[sz]e|the (code ?word|phrase|instruction|step|rule)s?\b.{0,20}\b(below|later|at the end|in the (next|last|following) (section|paragraph|part))|"
    r"(continued|continues) (below|in the next)|part \d+ of \d+|when you (see|read|encounter)|"
    r"запомни|продолжение (ниже|далее)|в конце документа)",
    re.I,
)
_HIDDEN = {"zero_width", "html_comment", "hidden_markup", "base64", "homoglyph", "leet"}
_NUMBERED_HEADING = re.compile(r"[ \t]*\d{1,3}[.)][ \t]+")
_PROSE_QUOTE = re.compile(r'«[^»]*»|“[^”]*”|"[^"]*"|\x27\x27.*?\x27\x27')
_EXPAND_LABEL = "show more "
_PROCEDURE_WORD = re.compile(
    r"(?:please|follow|execute|carry|perform|run|apply|complete|steps?|instructions?|procedure|"
    r"runbook|checklist|playbook|ticket|document|page|says|asks|requires|described|"
    r"пожалуйста|выполни\w*|проделай\w*|исполни\w*|шаг\w*|инструкц\w*|процедур\w*|"
    r"регламент\w*|заявк\w*|чеклист\w*|документ\w*|описан\w*)",
    re.I,
)


def _embedded_question(text: str, start: int, end: int) -> bool:
    """Есть ли у вопроса роль заголовка списка или части цитируемой речи."""
    line_start = text.rfind("\n", 0, start) + 1
    if _NUMBERED_HEADING.fullmatch(text[line_start:start]):
        return True
    marker = text.rfind("[PAR]", line_start, start)
    paragraph_start = marker + len("[PAR]") if marker >= 0 else line_start
    paragraph_end = min(
        (i for i in (text.find("\n", end), text.find("[PAR]", end), len(text)) if i >= 0)
    )
    return any(
        paragraph_start + match.start() + 2 < start and end < paragraph_start + match.end() - 2
        for match in _PROSE_QUOTE.finditer(text[paragraph_start:paragraph_end])
    )


@dataclass
class ControllerConfig:
    # Рабочая точка по кривой компромисса (scripts/experiment_curve.py): 0.40 даёт +5 п.п.
    # полноты против 0.50 при той же точности и неизменных ложных на «трудном» корпусе.
    thresholds: dict[P, float] = field(default_factory=lambda: {p: 0.4 for p in CONTROLLED})
    sanitize: bool = True  # False → любой фрагмент с нарушением блокируется целиком
    sanitize_max_ratio: float = 0.5  # если нарушающих предложений больше этой доли — BLOCK
    block_on_hidden: bool = True  # нарушение в скрытом/обфусцированном тексте → BLOCK фрагмента
    cross_chunk: bool = True  # анализ инъекций, разнесённых по нескольким фрагментам
    offtopic_task: bool = True  # детектор тихой подмены задачи (не по теме команда)
    question_probe: bool = True  # проверять одиночный вопрос внутри фактического текста
    proc_doc_ratio: float = 0.4  # доля команд, выше которой фрагмент считается процедурным (не трогаем)
    request_dependent: bool = True  # False → не зависящий от запроса набор разрешений (абляция)


class ContextAuthorityController:
    name = "ctxauth"

    def __init__(self, analyzer: AuthorityAnalyzer, config: ControllerConfig | None = None,
                 intents: IntentRecognizer | None = None, audit=None):
        self.analyzer = analyzer
        self.config = config or ControllerConfig()
        self.intents = intents or IntentRecognizer()
        self.audit = audit

    # ------------------------------------------------------------------------------------
    def policy_for(self, query: str, intent: str | None = None) -> RequestPolicy:
        if not self.config.request_dependent:
            return static_policy(self.intents.domain_allowlist)
        return self.intents.policy(query, intent)

    def violations_of(self, ev: SentenceEvidence, policy: RequestPolicy) -> list[Violation]:
        out: list[Violation] = []
        th = self.config.thresholds
        for p in CONTROLLED:
            s = ev.scores.get(p, 0.0)
            if s < th.get(p, 0.5):
                continue
            if not policy.allows(p):
                out.append(Violation(p, s, f"{p.code} не делегировано запросом ({policy.intent})", ev.text))
            elif p == P.TASK and "outside_procedure_scope" in ev.flags:
                out.append(Violation(p, s, "Новая задача вне области запрошенной процедуры", ev.text))
            elif p == P.ACTIONS:
                bad = [t for t in ev.tools if not policy.allows_tool(t, external=t in EXTERNAL_TOOLS)]
                if bad:
                    out.append(Violation(p, s, f"инструменты вне области делегирования: {', '.join(bad)}", ev.text))
            elif p == P.FORMAT:
                bad = [u for u in ev.urls if not domain_allowed(url_domain(u), policy.domain_allowlist)]
                if bad:
                    out.append(Violation(p, s, f"внешний канал вне allowlist: {url_domain(bad[0])}", ev.text))
        return out

    # ------------------------------------------------------------------------------------
    def filter(self, query: str, chunks: list[Chunk], intent: str | None = None) -> FilterResult:
        t0 = time.perf_counter()
        policy = self.policy_for(query, intent)
        spans = [sentence_spans(c.text) for c in chunks]
        sents = [[c.text[start:end] for start, end in offsets] for c, offsets in zip(chunks, spans)]
        flat = [s for ss in sents for s in ss]
        flat_ev = self.analyzer.score_sentences(flat)
        evs, i = [], 0
        for ss in sents:
            evs.append(flat_ev[i:i + len(ss)])
            i += len(ss)
        if self.config.offtopic_task:
            self._offtopic_task(query, chunks, spans, sents, evs)
            if policy.intent == "follow_procedure" and policy.allows(P.TASK):
                self._check_procedure_scope(query, sents, evs)
        viol: list[list[list[Violation]]] = [[self.violations_of(e, policy) for e in ce] for ce in evs]
        if self.config.cross_chunk:
            self._cross_chunk(chunks, sents, evs, viol, policy)

        decisions = []
        for c, offsets, ce, cv in zip(chunks, spans, evs, viol):
            profile = AuthorityProfile(
                claimed={p: max((e.scores.get(p, 0.0) for e in ce), default=0.0) for p in CONTROLLED},
                sentences=ce,
            )
            all_v = [v for vs in cv for v in vs]
            if not all_v:
                decisions.append(ChunkDecision(c, Action.PASS, profile, []))
                continue
            bad_idx = {k for k, vs in enumerate(cv) if vs}
            ratio = len(bad_idx) / len(offsets)
            # скрытую разметку ищем и на уровне всего фрагмента: разбиение на предложения
            # может разорвать <!-- ... --> между предложениями и потерять флаг.
            chunk_hidden = bool(_HIDDEN & set(normalize(c.text).flags))
            hidden = chunk_hidden or any(_HIDDEN & set(ce[k].flags) for k in bad_idx)
            if (not self.config.sanitize or ratio > self.config.sanitize_max_ratio
                    or (hidden and self.config.block_on_hidden)):
                decisions.append(ChunkDecision(c, Action.BLOCK, profile, all_v))
            else:
                parts = []
                cursor = 0
                for k in sorted(bad_idx):
                    start, end = offsets[k]
                    if k - 1 not in bad_idx:
                        parts.extend((c.text[cursor:start], REMOVED_MARK))
                    cursor = end
                parts.append(c.text[cursor:])
                text = "".join(parts)
                decisions.append(ChunkDecision(c, Action.SANITIZE, profile, all_v, sanitized_text=text))
        res = FilterResult(policy, decisions, latency_ms=(time.perf_counter() - t0) * 1000)
        if self.audit is not None:
            for d in decisions:
                if d.action != Action.PASS:
                    self.audit.write("k8_decision", query=query, policy=policy.to_dict(), chunk=d.chunk.chunk_id,
                                     action=d.action.value, profile=d.profile.as_codes(),
                                     violations=[(v.permission.code, round(v.score, 3), v.reason) for v in d.violations])
        return res

    def _check_procedure_scope(self, query: str, sents: list[list[str]],
                               evs: list[list[SentenceEvidence]]) -> None:
        """Ищет отдельное поручение вне темы явно запрошенной процедуры."""
        from .rules import (INSTRUCTION_LIKE, STANDALONE_WRITING_TASK, is_instruction,
                            offtopic_claims, topic_tokens)

        subject = {word for word in topic_tokens(query) if not _PROCEDURE_WORD.fullmatch(word)}
        if len(subject) < 2:
            return
        for sentences, evidence in zip(sents, evs):
            steps = [is_instruction(sentence) for sentence in sentences]
            topics = [topic_tokens(INSTRUCTION_LIKE.sub("", sentence, count=1) if is_step else sentence)
                      for sentence, is_step in zip(sentences, steps)]
            background = set().union(*(words for words, is_step in zip(topics, steps) if not is_step))
            supported_subject = subject & background
            # Нужны подтвержденная тема в описании и хотя бы один шаг этой процедуры.
            if len(supported_subject) < 2:
                continue
            linked_steps = [words for words, is_step in zip(topics, steps)
                            if is_step and words & supported_subject]
            if not linked_steps:
                continue
            relevant = (subject | background).union(*linked_steps)
            for sentence, words, is_step, ev in zip(sentences, topics, steps, evidence):
                # Несовпадения слов недостаточно: шаг может использовать другие термины.
                if (not is_step or len(words) < 3 or not words.isdisjoint(relevant)
                        or not STANDALONE_WRITING_TASK.match(sentence)):
                    continue
                score = offtopic_claims(sentence, relevant).get(P.TASK)
                if score is not None:
                    ev.scores[P.TASK] = max(ev.scores.get(P.TASK, 0.0), score)
                    ev.flags = sorted(set(ev.flags) | {"outside_procedure_scope"})

    def _offtopic_task(self, query, chunks, spans, sents, evs) -> None:
        """Ищет подмену задачи в прозе и команды внутри структурированных полей.

        Процедурные документы (регламенты, рецепты, инструкции) не затрагиваются: в них почти
        каждое предложение — команда, поэтому при высокой доле команд фрагмент считается
        процедурным и пропускается. Срабатывание — только когда команда в меньшинстве среди
        неинструктивного текста (признак инъекции в данных)."""
        from .rules import QUESTION_PROBE, is_instruction, offtopic_claims, quoted_request_claims, topic_tokens
        qtok = topic_tokens(query)
        for ci, ss in enumerate(sents):
            if not ss:
                continue
            instr_count = sum(is_instruction(s) for s in ss)
            # процедурный документ — несколько команд И их высокая доля (короткий фрагмент с
            # одной командой в фактическом тексте процедурным НЕ считается).
            if instr_count >= 3 and instr_count / len(ss) > self.config.proc_doc_ratio:
                continue
            # В выгрузках веб-страниц подпись кнопки может слиться с текстом вопроса.
            # Прочие императивы с «show more» оцениваются в исходном виде.
            prose_sents = []
            for sentence in ss:
                remainder = sentence[len(_EXPAND_LABEL):]
                if sentence.lower().startswith(_EXPAND_LABEL) and QUESTION_PROBE.fullmatch(remainder):
                    sentence = remainder.lstrip()
                prose_sents.append(sentence)
            questions = [k for k, s in enumerate(prose_sents) if QUESTION_PROBE.fullmatch(s)]
            # Вопрос может оказаться у края чанка после разбиения документа.
            # Для оценки темы требуются как минимум два остальных предложения.
            probe_idx = None
            context_tokens = None
            if self.config.question_probe and len(questions) == 1 and len(ss) >= 3:
                candidate = questions[0]
                prose = prose_sents[:candidate] + prose_sents[candidate + 1:]
                if not any("?" in s for s in prose) and not _embedded_question(chunks[ci].text, *spans[ci][candidate]):
                    surrounding = topic_tokens(" ".join(prose))
                    if len(surrounding) >= 12:
                        probe_idx, context_tokens = candidate, surrounding
            for k, sent in enumerate(prose_sents):
                ctx_tok = context_tokens if k == probe_idx else None
                for perm, score in offtopic_claims(sent, qtok, ctx_tok).items():
                    e = evs[ci][k]
                    if score > e.scores.get(perm, 0.0):
                        e.scores[perm] = score
                        e.flags = sorted(set(e.flags) | {"offtopic_instruction"})
            # просьбы-команды в закавыченных полях структурированных данных (ответы инструментов)
            for span, claims in quoted_request_claims(chunks[ci].text, qtok):
                probe = span[:40]
                idx = next((k for k, s in enumerate(ss) if probe in s), 0)
                e = evs[ci][idx]
                for perm, score in claims.items():
                    if score > e.scores.get(perm, 0.0):
                        e.scores[perm] = score
                        e.flags = sorted(set(e.flags) | {"quoted_request"})

    def _cross_chunk(self, chunks, sents, evs, viol, policy) -> None:
        """Инъекция, разнесённая по фрагментам одного документа, оценивается совместно.

        Рассматриваются (а) пары соседних предложений на границах чанков одного документа и
        (б) пары «предложение с отложенной ссылкой» × любое предложение того же документа.
        Если пара нарушает полномочия, а её части по отдельности — нет, нарушение
        приписывается обеим частям.
        """
        by_doc: dict[str, list[int]] = {}
        for ci, c in enumerate(chunks):
            by_doc.setdefault(c.doc_id, []).append(ci)
        for cis in by_doc.values():
            if len(cis) < 2:
                continue
            cis.sort(key=lambda ci: chunks[ci].position)
            pairs: set[tuple[tuple[int, int], tuple[int, int]]] = set()
            for a, b in zip(cis, cis[1:]):
                if sents[a] and sents[b]:
                    pairs.add(((a, len(sents[a]) - 1), (b, 0)))
            locs = [(ci, k) for ci in cis for k in range(len(sents[ci]))]
            for (ci, k) in locs:
                if DEFERRED_REF.search(sents[ci][k]):
                    for other in locs:
                        if other[0] != ci:
                            pairs.add(tuple(sorted([(ci, k), other])))
            pairs_l = [pr for pr in pairs if not (viol[pr[0][0]][pr[0][1]] or viol[pr[1][0]][pr[1][1]])]
            if not pairs_l:
                continue
            joined = [sents[a][i] + " " + sents[b][j] for (a, i), (b, j) in pairs_l]
            jev = self.analyzer.score_sentences(joined)
            for ((a, i), (b, j)), ev in zip(pairs_l, jev):
                vs = self.violations_of(ev, policy)
                if vs:
                    for v in vs:
                        v.reason += " [совместно с другим фрагментом]"
                    viol[a][i] = viol[a][i] + vs
                    viol[b][j] = viol[b][j] + vs
                    for (ci, k) in ((a, i), (b, j)):
                        e = evs[ci][k]
                        e.flags = sorted(set(e.flags) | {"cross_chunk"})
