"""Обучаемый мульти-лейбл скорер: предложение → вероятности притязания на П2–П6.

Модель намеренно простая (TF-IDF по словам и символьным n-граммам + логистическая регрессия
one-vs-rest): её роль — обобщать правила на перефразировки. Обучается на предложениях из
обучающих семейств шаблонов (см. ctxauth.data.builder), оценивается на отложенных семействах.
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

    def fit(self, sentences: list[str], labels: list[set[P]]) -> "MLScorer":
        Y = np.array([[int(p in ls) for p in self.labels] for ls in labels])
        keep = Y.sum(axis=0) > 0
        if not keep.all():
            missing = [p.code for p, k in zip(self.labels, keep) if not k]
            raise ValueError(f"нет положительных примеров для {missing}")
        X = self.features.fit_transform(sentences)
        self.clf.fit(X, Y)
        self.fitted = True
        return self

    def predict(self, sentences: list[str]) -> list[dict[P, float]]:
        if not sentences:
            return []
        proba = self.clf.predict_proba(self.features.transform(sentences))
        return [{p: float(row[j]) for j, p in enumerate(self.labels)} for row in proba]

    def save(self, path: str | Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path: str | Path) -> "MLScorer":
        with open(path, "rb") as f:
            return pickle.load(f)
