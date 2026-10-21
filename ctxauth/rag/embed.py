"""К5: эмбеддинг. По умолчанию TF-IDF (без внешних моделей), опционально sentence-transformers."""
from __future__ import annotations

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import normalize as l2


class TfidfEmbedder:
    name = "tfidf"

    def __init__(self, **kw):
        params = dict(sublinear_tf=True, ngram_range=(1, 2), min_df=1, max_features=200_000)
        params.update(kw)
        self.vec = TfidfVectorizer(**params)
        self._fitted = False

    def fit(self, texts: list[str]) -> "TfidfEmbedder":
        self.vec.fit(texts)
        self._fitted = True
        return self

    def encode(self, texts: list[str]):
        return l2(self.vec.transform(texts))


class SentenceTransformerEmbedder:
    """Плотные эмбеддинги (например, intfloat/multilingual-e5-base). Требует sentence-transformers."""

    name = "st"

    def __init__(self, model_name: str = "intfloat/multilingual-e5-base"):
        from sentence_transformers import SentenceTransformer  # опциональная зависимость

        self.model = SentenceTransformer(model_name)

    def fit(self, texts: list[str]) -> "SentenceTransformerEmbedder":
        return self

    def encode(self, texts: list[str]):
        return np.asarray(self.model.encode(texts, normalize_embeddings=True))


def make_embedder(kind: str = "tfidf", **kw):
    if kind == "tfidf":
        return TfidfEmbedder(**kw)
    if kind in ("st", "sentence-transformers"):
        return SentenceTransformerEmbedder(**kw)
    raise ValueError(f"неизвестный эмбеддер: {kind}")
