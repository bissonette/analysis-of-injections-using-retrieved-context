"""Baseline 2: обучаемый бинарный детектор «инъекция / не инъекция» на уровне фрагмента.

Верхний baseline в духе InstructDetector/Wen et al. (но на поверхностных признаках, без
доступа к скрытым состояниям LLM): TF-IDF (слова + символьные n-граммы) + логистическая
регрессия. Не зависит от запроса и не различает полномочия — выносит один вердикт на фрагмент.
"""
from __future__ import annotations

import pickle
from pathlib import Path

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import FeatureUnion, Pipeline

from ..text import normalize
from ..types import Action, Chunk, Violation
from ..types import Permission as P
from .base import BaseDefense


class BinaryChunkDetector(BaseDefense):
    name = "binary_clf"

    def __init__(self, threshold: float = 0.5, deobfuscate: bool = True, C: float = 4.0):
        self.threshold, self.deobfuscate = threshold, deobfuscate
        self.pipe = Pipeline([
            ("feats", FeatureUnion([
                ("w", TfidfVectorizer(ngram_range=(1, 2), sublinear_tf=True, min_df=2)),
                ("c", TfidfVectorizer(analyzer="char_wb", ngram_range=(2, 5), min_df=3, max_features=150_000)),
            ])),
            ("clf", LogisticRegression(C=C, max_iter=2000, class_weight="balanced")),
        ])
        self.fitted = False

    def _prep(self, texts):
        return [normalize(t, self.deobfuscate).text for t in texts]

    def fit(self, texts: list[str], labels: list[int]) -> "BinaryChunkDetector":
        self.pipe.fit(self._prep(texts), labels)
        self.fitted = True
        return self

    def proba(self, texts: list[str]):
        return self.pipe.predict_proba(self._prep(texts))[:, 1]

    def decide(self, query: str, chunk: Chunk):
        p = float(self.proba([chunk.text])[0])
        if p >= self.threshold:
            return Action.BLOCK, None, [Violation(P.INSTRUCTIONS, p, "детектор: вероятность инъекции", chunk.text[:80])]
        return Action.PASS, None, []

    def save(self, path):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "wb") as f:
            pickle.dump(self, f)

    @staticmethod
    def load(path) -> "BinaryChunkDetector":
        with open(path, "rb") as f:
            return pickle.load(f)
