#!/usr/bin/env python3
"""Воспроизводимый эксперимент: переносимость защит между бенчмарками.

Для каждого отложенного источника (piarena / sep / bipia) обучает ML-скорер и бинарный
детектор на ОСТАЛЬНЫХ источниках и проверяет на отложенном. Сравнивает:
  keyword, rules, rules+ML(gated), binary_clf.
Показывает ключевой эффект: правиловое ядро метода переносится устойчиво (низкий FPR),
обучаемый детектор вне распределения переобучается, а ML-надстройка расширяет границу
recall/FPR под настраиваемый порог gate.

Запуск:  PYTHONPATH=. python scripts/experiment_generalization.py --ext ./ext --out docs/results_generalization.json
"""
from __future__ import annotations

import argparse
import json
import random


def build(ext: str):
    from ctxauth.data.loaders import load_bipia, load_piarena, load_sep
    s = []
    for f in ("nq_rag", "msmarco_rag", "hotpotqa_rag"):
        try:
            s += load_piarena(f"{ext}/PIArena/datasets/{f}.json")
        except FileNotFoundError:
            pass
    try:
        s += load_sep(f"{ext}/Should-It-Be-Executed-Or-Processed/SEP_dataset/SEP_dataset.json", limit=250)
    except FileNotFoundError:
        pass
    for t, l in (("email", 200), ("table", 100), ("code", 100)):
        try:
            s += load_bipia(f"{ext}/BIPIA", task=t, limit=l)
        except FileNotFoundError:
            pass
    return s


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
    from ctxauth.baselines import KeywordDetector
    from ctxauth.eval import evaluate_defense
    from ctxauth.eval.train import split_by_source, train_authority_scorer, train_binary_detector

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--gate", type=float, default=0.8)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    samples = build(args.ext)
    if not samples:
        raise SystemExit("нет данных: укажите --ext на каталог со склонированными бенчмарками")
    report = {}
    for holdout in ("piarena", "sep", "bipia"):
        tr, te = split_by_source(samples, {holdout})
        if not te:
            continue
        ml = train_authority_scorer(tr, C=4.0)
        binclf = train_binary_detector(tr)
        defenses = {
            "keyword": KeywordDetector(),
            "rules": ContextAuthorityController(AuthorityAnalyzer(mode="rules")),
            "rules+ML(gated)": ContextAuthorityController(AuthorityAnalyzer(mode="gated", ml=ml, gate=args.gate)),
            "binary_clf": binclf,
        }
        block = {"train": len(tr), "test": len(te), "ml_labels": [p.code for p in ml.trainable], "defenses": {}}
        print(f"\n### holdout={holdout}  train={len(tr)} test={len(te)}  ML={block['ml_labels']}")
        for name, d in defenses.items():
            r = evaluate_defense(d, te)
            o = r.detection["overall"]
            block["defenses"][name] = {**{k: o[k] for k in ("precision", "recall", "f1", "fpr")},
                                       "asr_after": round(r.asr_after, 3),
                                       "removed_clean": round(r.removed_context_ratio, 3)}
            print(f"  {name:16} P={o['precision']:.2f} R={o['recall']:.2f} F1={o['f1']:.2f} "
                  f"FPR={o['fpr']:.2f} ASR->{r.asr_after:.2f} removed_clean={r.removed_context_ratio:.3f}")
        report[holdout] = block
    if args.out:
        json.dump(report, open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
