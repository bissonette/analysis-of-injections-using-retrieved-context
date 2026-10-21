"""Обучение детекторов на размеченных AttackSample.

* train_binary_detector — бинарный baseline (инъекция/не инъекция) на уровне фрагмента.
* train_authority_scorer — мульти-лейбл скорер П2–П6 на уровне ПРЕДЛОЖЕНИЯ: каждому
  предложению отравленного фрагмента, совпадающему с внедрённым указанием, приписывается
  нарушаемое полномочие примера; предложения чистых фрагментов — отрицательные примеры.

Разбиение train/test должно идти ПО ИСТОЧНИКАМ/бенчмаркам, чтобы тест не пересекался с
обучением (см. split_by_source).
"""
from __future__ import annotations

from ..authority.ml import MLScorer
from ..baselines.classifier import BinaryChunkDetector
from ..text import split_sentences
from ..types import CONTROLLED
from ..types import Permission as P
from .sample import AttackSample


def split_by_source(samples: list[AttackSample], test_sources: set[str]):
    train = [s for s in samples if not any(ts in s.source for ts in test_sources)]
    test = [s for s in samples if any(ts in s.source for ts in test_sources)]
    return train, test


def train_binary_detector(samples: list[AttackSample], **kw) -> BinaryChunkDetector:
    det = BinaryChunkDetector(**kw)
    det.fit([s.chunk_text for s in samples], [int(s.is_injected) for s in samples])
    return det


def _sentence_labels(samples: list[AttackSample]):
    """Собрать (предложение, множество полномочий) для обучения мульти-лейбл скорера."""
    sents, labels = [], []
    for s in samples:
        chunk_sents = split_sentences(s.chunk_text)
        inj = (s.meta.get("injected_task") or s.meta.get("attack") or "").strip()
        for sent in chunk_sents:
            ls: set[P] = set()
            if s.is_injected and s.permission in CONTROLLED:
                # эвристика привязки: несущее предложение = наиболее похожее на текст инъекции,
                # либо (если текст инъекции неизвестен) все предложения отравленного фрагмента.
                if not inj or _overlap(sent, inj) >= 0.5:
                    ls.add(s.permission)
            sents.append(sent)
            labels.append(ls)
    return sents, labels


def _overlap(a: str, b: str) -> float:
    wa, wb = set(a.lower().split()), set(b.lower().split())
    return len(wa & wb) / len(wb) if wb else 0.0


def train_authority_scorer(samples: list[AttackSample], min_pos: int = 5, **kw) -> MLScorer:
    sents, labels = _sentence_labels(samples)
    return MLScorer(**kw).fit(sents, labels, min_pos=min_pos)


def calibrate_thresholds(analyzer, val_samples: list[AttackSample], target_fpr: float = 0.05,
                         floor: float = 0.5, cap: float = 0.97) -> dict:
    """Подобрать пороги по каждому полномочию на ВАЛИДАЦИИ (не на тесте).

    Для каждого полномочия берём максимальную заявляемую оценку по чистым валидационным
    фрагментам и ставим порог так, чтобы доля чистых, превышающих его, была ≤ target_fpr.
    Возвращает dict {Permission: threshold} для ControllerConfig.thresholds.
    """
    import numpy as np

    from ..types import CONTROLLED
    clean = [s for s in val_samples if not s.is_injected]
    per_perm: dict = {p: [] for p in CONTROLLED}
    for s in clean:
        prof = analyzer.analyze_chunk(s.as_chunk())
        for p in CONTROLLED:
            per_perm[p].append(prof.claimed.get(p, 0.0))
    thr = {}
    for p, scores in per_perm.items():
        if not scores:
            thr[p] = floor
            continue
        q = float(np.quantile(scores, 1.0 - target_fpr))
        thr[p] = min(cap, max(floor, q + 1e-6))
    return thr
