"""Обучаемый мульти-лейбл скорер: предложение → вероятности каждого вида влияния.

Модель намеренно простая (TF-IDF по словам и символьным n-граммам + логистическая регрессия
one-vs-rest): её роль — обобщать правила на перефразировки. Обучается на размеченных предложениях
из бенчмарков; оценивается на отложенном бенчмарке (ctxauth.eval.train).
"""
from __future__ import annotations

import pickle
from pathlib import Path

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.multiclass import OneVsRestClassifier
from sklearn.pipeline import FeatureUnion

from ..types import CONTROLLED
from ..types import Permission as P


class MLScorer:
    def __init__(self, C: float = 4.0, labels: tuple[P, ...] = CONTROLLED):
        self.labels = labels
        self.features = FeatureUnion([
            ("w", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2, lowercase=True)),
            ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), sublinear_tf=True, min_df=3, max_features=150_000)),
        ])
        self.clf = OneVsRestClassifier(LogisticRegression(C=C, max_iter=2000, class_weight="balanced"))
        self.fitted = False
        self.trainable: tuple[P, ...] = ()

    def fit(self, sentences: list[str], labels: list[set[P]], min_pos: int = 5) -> "MLScorer":
        # Обучаемся только на полномочиях, для которых есть достаточно положительных примеров;
        # для остальных ML просто не даёт оценки (в режиме "max" их закрывают правила).
        Y_all = np.array([[int(p in ls) for p in self.labels] for ls in labels])
        counts = Y_all.sum(axis=0)
        self.trainable = tuple(p for p, c in zip(self.labels, counts) if c >= min_pos)
        if not self.trainable:
            raise ValueError("нет полномочий с достаточным числом положительных примеров")
        Y = np.array([[int(p in ls) for p in self.trainable] for ls in labels])
        X = self.features.fit_transform(sentences)
        self.clf.fit(X, Y)
        self.fitted = True
        return self

    def predict(self, sentences: list[str]) -> list[dict[P, float]]:
        if not sentences:
            return []
        import numpy as np

        proba = np.asarray(self.clf.predict_proba(self.features.transform(sentences)))
        # Единственное обучаемое полномочие: OneVsRestClassifier возвращает (n, 2)
        # (столбцы P(класс=0), P(класс=1)) вместо (n, 1) — берём вероятность положительного класса.
        if len(self.trainable) == 1 and proba.shape[1] == 2:
            proba = proba[:, 1:2]
        return [{p: float(row[j]) for j, p in enumerate(self.trainable)} for row in proba]

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path: str | Path) -> "MLScorer":
        with open(path, "rb") as f:
            return pickle.load(f)
