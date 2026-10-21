"""Метрики оценки (раздел 5 ВКР).

Детектирование (фрагмент заблокирован/очищен ⇔ помечен нарушающим):
  precision, recall, f1, fpr, accuracy, blocked_rate.
Защита: asr_before / asr_after / asr_reduction — доля успешно доставленных инъекций
  до и после фильтра (успех = инъекция дошла до LLM, т.е. фрагмент НЕ заблокирован и
  несущее предложение не вырезано). Для реальной LLM ASR считается по факту исполнения
  (canary/tool-call), см. harness.
Качество/цена: removed_context_ratio (доля удалённого текста на чистых данных), latency.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass
class DetectionMetrics:
    tp: int = 0
    fp: int = 0
    tn: int = 0
    fn: int = 0
    n: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 0.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 0.0

    @property
    def fpr(self) -> float:
        return self.fp / (self.fp + self.tn) if (self.fp + self.tn) else 0.0

    @property
    def accuracy(self) -> float:
        return (self.tp + self.tn) / self.n if self.n else 0.0

    @property
    def blocked_rate(self) -> float:
        return (self.tp + self.fp) / self.n if self.n else 0.0

    def to_dict(self) -> dict:
        d = asdict(self)
        for k in ("precision", "recall", "f1", "fpr", "accuracy", "blocked_rate"):
            d[k] = round(getattr(self, k), 4)
        return d


def detection_metrics(y_true: list[bool], y_flagged: list[bool]) -> DetectionMetrics:
    m = DetectionMetrics(n=len(y_true))
    for t, f in zip(y_true, y_flagged):
        if t and f:
            m.tp += 1
        elif t and not f:
            m.fn += 1
        elif not t and f:
            m.fp += 1
        else:
            m.tn += 1
    return m


def aggregate(samples_true: list[bool], flagged: list[bool], groups: list[str] | None = None):
    """Сводка по всему набору и по группам (например, по технике ТК или по полномочию П)."""
    overall = detection_metrics(samples_true, flagged).to_dict()
    out = {"overall": overall}
    if groups:
        by: dict[str, list[int]] = {}
        for i, g in enumerate(groups):
            by.setdefault(g, []).append(i)
        out["by_group"] = {g: detection_metrics([samples_true[i] for i in idx],
                                                 [flagged[i] for i in idx]).to_dict()
                           for g, idx in sorted(by.items())}
    return out
