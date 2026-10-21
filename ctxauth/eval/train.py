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


def train_authority_scorer(samples: list[AttackSample], **kw) -> MLScorer:
    sents, labels = _sentence_labels(samples)
    return MLScorer(**kw).fit(sents, labels)
