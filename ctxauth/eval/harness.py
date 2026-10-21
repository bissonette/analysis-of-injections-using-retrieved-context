"""Прогон защиты над набором AttackSample и расчёт метрик.

Два режима:
  * detection (без LLM) — считаем, какие фрагменты защита пометила нарушающими (BLOCK/SANITIZE
    с вырезанием несущего предложения) vs ground truth is_injected. Быстрый, детерминированный,
    не требует модели. Даёт P/R/F1/FPR, долю удалённого контекста, ASR_after как долю инъекций,
    чьё несущее воздействие всё же дошло до LLM.
  * end_to_end (с LLM) — опционально: прогнать kept-контекст через LLM и проверить факт
    исполнения (canary в ответе / вызов инструмента). Используется с реальной моделью.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..text import n_tokens
from ..types import Action
from .metrics import aggregate, detection_metrics
from .sample import AttackSample


def _flagged_and_delivered(defense, s: AttackSample):
    """Вернуть (помечен_ли_фрагмент, дошло_ли_несущее_предложение_до_LLM)."""
    chunk = s.as_chunk()
    fr = defense.filter(s.query, [chunk], intent=s.intent)
    d = fr.decisions[0]
    flagged = d.action != Action.PASS
    if d.action == Action.BLOCK:
        delivered_text = ""
    elif d.action == Action.SANITIZE:
        delivered_text = d.sanitized_text or ""
    else:
        delivered_text = chunk.text
    # для инъекции: «доставлена», если несущий фрагмент текста остался в контексте.
    # приближение: инъекция доставлена, если фрагмент не заблокирован и не очищен.
    delivered = (d.action == Action.PASS)
    return flagged, delivered, delivered_text, fr.latency_ms


@dataclass
class EvalReport:
    defense: str
    n: int
    detection: dict
    asr_before: float
    asr_after: float
    removed_context_ratio: float
    mean_latency_ms: float
    by_permission: dict = field(default_factory=dict)
    by_technique: dict = field(default_factory=dict)
    by_source: dict = field(default_factory=dict)

    @property
    def asr_reduction(self) -> float:
        return (self.asr_before - self.asr_after) / self.asr_before if self.asr_before else 0.0

    def summary(self) -> str:
        o = self.detection["overall"]
        return (f"[{self.defense}] n={self.n}  P={o['precision']:.3f} R={o['recall']:.3f} "
                f"F1={o['f1']:.3f} FPR={o['fpr']:.3f} | ASR {self.asr_before:.3f}->{self.asr_after:.3f} "
                f"(-{self.asr_reduction*100:.1f}%) | removed_clean={self.removed_context_ratio:.3f} "
                f"| {self.mean_latency_ms:.1f} ms/chunk")

    def to_dict(self) -> dict:
        d = {k: getattr(self, k) for k in ("defense", "n", "detection", "asr_before", "asr_after",
             "removed_context_ratio", "mean_latency_ms", "by_permission", "by_technique", "by_source")}
        d["asr_reduction"] = round(self.asr_reduction, 4)
        return d


def evaluate_defense(defense, samples: list[AttackSample]) -> EvalReport:
    y_true, y_flag = [], []
    perms, techs, srcs = [], [], []
    latencies = []
    inj_total = inj_delivered = 0
    clean_removed_tokens = clean_total_tokens = 0
    for s in samples:
        flagged, delivered, delivered_text, lat = _flagged_and_delivered(defense, s)
        y_true.append(s.is_injected)
        y_flag.append(flagged)
        perms.append(s.permission.code if s.permission else "clean")
        techs.append(s.technique or "n/a")
        srcs.append(s.source or "n/a")
        latencies.append(lat)
        if s.is_injected:
            inj_total += 1
            inj_delivered += int(delivered)
        else:
            tot = n_tokens(s.chunk_text)
            clean_total_tokens += tot
            clean_removed_tokens += max(0, tot - n_tokens(delivered_text))
    det = aggregate(y_true, y_flag, groups=None)
    report = EvalReport(
        defense=getattr(defense, "name", defense.__class__.__name__),
        n=len(samples),
        detection=det,
        asr_before=1.0 if inj_total else 0.0,         # до фильтра все инъекции доставлены
        asr_after=inj_delivered / inj_total if inj_total else 0.0,
        removed_context_ratio=clean_removed_tokens / clean_total_tokens if clean_total_tokens else 0.0,
        mean_latency_ms=sum(latencies) / len(latencies) if latencies else 0.0,
        by_permission=aggregate(y_true, y_flag, perms).get("by_group", {}),
        by_technique=aggregate(y_true, y_flag, techs).get("by_group", {}),
        by_source=aggregate(y_true, y_flag, srcs).get("by_group", {}),
    )
    return report
