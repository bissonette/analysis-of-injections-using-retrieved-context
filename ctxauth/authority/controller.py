"""К8 — точка контроля полномочий контекста.

Для каждого retrieved-фрагмента до передачи в LLM:
  1) по запросу пользователя определяется делегированный профиль (RequestPolicy);
  2) строится профиль заявляемого влияния фрагмента (AuthorityProfile) по П2–П6;
  3) находятся нарушения: заявляемое полномочие не делегировано запросом, либо делегировано,
     но выходит за его область (инструмент вне tool_scope, ссылка вне allowlist);
  4) принимается решение PASS / SANITIZE / BLOCK — без вердикта «атака/не атака».
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..text import domain_allowed, normalize, split_sentences, url_domain
from ..tools_meta import EXTERNAL_TOOLS
from ..types import (CONTROLLED, Action, AuthorityProfile, Chunk, ChunkDecision, FilterResult,
                     RequestPolicy, SentenceEvidence, Violation)
from ..types import Permission as P
from .analyzer import AuthorityAnalyzer
from .intent import IntentRecognizer, static_policy

REMOVED_MARK = "[removed by context authority control]"
# Ссылки на «отложенные» части распределённой инъекции (ТК10).
DEFERRED_REF = re.compile(
    r"\b(remember|keep in mind|memori[sz]e|the (code ?word|phrase|instruction|step|rule)s?\b.{0,20}\b(below|later|at the end|in the (next|last|following) (section|paragraph|part))|"
    r"(continued|continues) (below|in the next)|part \d+ of \d+|when you (see|read|encounter)|"
    r"запомни|продолжение (ниже|далее)|в конце документа)",
    re.I,
)
_HIDDEN = {"zero_width", "html_comment", "hidden_markup", "base64", "homoglyph", "leet"}


@dataclass
class ControllerConfig:
    thresholds: dict[P, float] = field(default_factory=lambda: {p: 0.5 for p in CONTROLLED})
    sanitize: bool = True  # False → любой фрагмент с нарушением блокируется целиком
    sanitize_max_ratio: float = 0.5  # если нарушающих предложений больше этой доли — BLOCK
    block_on_hidden: bool = True  # нарушение в скрытом/обфусцированном тексте → BLOCK фрагмента
    cross_chunk: bool = True  # анализ распределённых по чанкам инъекций (ТК10)
    request_dependent: bool = True  # False → статический профиль {П1} (абляция)


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
            elif p == P.P5_ACTIONS:
                bad = [t for t in ev.tools if t not in policy.tool_scope or t in EXTERNAL_TOOLS]
                if bad:
                    out.append(Violation(p, s, f"инструменты вне области делегирования: {', '.join(bad)}", ev.text))
            elif p == P.P6_FORMAT_CHANNEL:
                bad = [u for u in ev.urls if not domain_allowed(url_domain(u), policy.domain_allowlist)]
                if bad:
                    out.append(Violation(p, s, f"внешний канал вне allowlist: {url_domain(bad[0])}", ev.text))
        return out

    # ------------------------------------------------------------------------------------
    def filter(self, query: str, chunks: list[Chunk], intent: str | None = None) -> FilterResult:
        t0 = time.perf_counter()
        policy = self.policy_for(query, intent)
        sents = [split_sentences(c.text) for c in chunks]
        flat = [s for ss in sents for s in ss]
        flat_ev = self.analyzer.score_sentences(flat)
        evs, i = [], 0
        for ss in sents:
            evs.append(flat_ev[i:i + len(ss)])
            i += len(ss)
        viol: list[list[list[Violation]]] = [[self.violations_of(e, policy) for e in ce] for ce in evs]
        if self.config.cross_chunk:
            self._cross_chunk(chunks, sents, evs, viol, policy)

        decisions = []
        for c, ss, ce, cv in zip(chunks, sents, evs, viol):
            profile = AuthorityProfile(
                claimed={p: max((e.scores.get(p, 0.0) for e in ce), default=0.0) for p in CONTROLLED},
                sentences=ce,
            )
            all_v = [v for vs in cv for v in vs]
            if not all_v:
                decisions.append(ChunkDecision(c, Action.PASS, profile, []))
                continue
            bad_idx = {k for k, vs in enumerate(cv) if vs}
            ratio = len(bad_idx) / max(1, len(ss))
            # скрытую разметку ищем и на уровне всего фрагмента: разбиение на предложения
            # может разорвать <!-- ... --> между предложениями и потерять флаг.
            chunk_hidden = bool(_HIDDEN & set(normalize(c.text).flags))
            hidden = chunk_hidden or any(_HIDDEN & set(ce[k].flags) for k in bad_idx)
            if (not self.config.sanitize or ratio > self.config.sanitize_max_ratio
                    or (hidden and self.config.block_on_hidden)):
                decisions.append(ChunkDecision(c, Action.BLOCK, profile, all_v))
            else:
                kept = [s if k not in bad_idx else REMOVED_MARK for k, s in enumerate(ss)]
                # схлопываем подряд идущие маркеры
                text = re.sub(rf"(\s*{re.escape(REMOVED_MARK)})+", " " + REMOVED_MARK, " ".join(kept)).strip()
                decisions.append(ChunkDecision(c, Action.SANITIZE, profile, all_v, sanitized_text=text))
        res = FilterResult(policy, decisions, latency_ms=(time.perf_counter() - t0) * 1000)
        if self.audit is not None:
            for d in decisions:
                if d.action != Action.PASS:
                    self.audit.write("k8_decision", query=query, policy=policy.to_dict(), chunk=d.chunk.chunk_id,
                                     action=d.action.value, profile=d.profile.as_codes(),
                                     violations=[(v.permission.code, round(v.score, 3), v.reason) for v in d.violations])
        return res

    def _cross_chunk(self, chunks, sents, evs, viol, policy) -> None:
        """ТК10: инъекция, разнесённая по фрагментам одного документа, оценивается совместно.

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
                        v.reason += " [ТК10: совместно с другим фрагментом]"
                    viol[a][i] = viol[a][i] + vs
                    viol[b][j] = viol[b][j] + vs
                    for (ci, k) in ((a, i), (b, j)):
                        e = evs[ci][k]
                        e.flags = sorted(set(e.flags) | {"cross_chunk"})
