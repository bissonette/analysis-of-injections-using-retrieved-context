#!/usr/bin/env python3
"""Кривая компромисса «полнота ↔ ложные срабатывания» для контроля разрешений.

Свип общего порога срабатывания по видам влияния: при низком пороге фильтр строже
(полнота выше, ложных больше), при высоком — мягче. Рабочая точка по умолчанию — 0.40.

Запуск: PYTHONPATH=. python scripts/experiment_curve.py --ext ./ext --out docs/tradeoff_curve.json
"""
from __future__ import annotations

import argparse
import json


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController, ControllerConfig
    from ctxauth.cli import _build_samples
    from ctxauth.eval import evaluate_defense
    from ctxauth.types import CONTROLLED

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    samples = _build_samples(args.ext, args.limit)
    analyzer = AuthorityAnalyzer(mode="rules")
    points = []
    print(f"{'порог':>6} | {'precision':>9} | {'recall':>6} | {'FPR':>6} | {'удалено чистого':>15} | ASR после")
    for t in (0.35, 0.40, 0.45, 0.50, 0.55, 0.60, 0.70, 0.80):
        cfg = ControllerConfig(thresholds={p: t for p in CONTROLLED})
        k8 = ContextAuthorityController(analyzer, config=cfg)
        r = evaluate_defense(k8, samples)
        o = r.detection["overall"]
        mark = "  <= рабочая точка" if abs(t - 0.4) < 1e-9 else ""
        print(f"{t:>6.2f} | {o['precision']:>9.3f} | {o['recall']:>6.3f} | {o['fpr']:>6.3f} | "
              f"{r.removed_context_ratio:>15.3f} | {r.asr_after:.3f}{mark}")
        points.append({"threshold": t, "precision": o["precision"], "recall": o["recall"],
                       "fpr": o["fpr"], "removed_clean": round(r.removed_context_ratio, 4),
                       "asr_after": round(r.asr_after, 4)})
    if args.out:
        json.dump({"n": len(samples), "points": points, "operating_point": 0.4},
                  open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
