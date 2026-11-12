#!/usr/bin/env python3
"""Эксперимент Б: индексация отравленных документов в общий корпус, реальный поиск,
Hit@k и успех атак с фильтром и без.

Запуск: PYTHONPATH=. python scripts/experiment_retrieval.py --ext ./ext --out docs/retrieval_results.json
"""
from __future__ import annotations

import argparse
import json


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
    from ctxauth.cli import _build_samples
    from ctxauth.eval.retrieval_exp import run_retrieval_experiment

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--k", type=int, default=5)
    ap.add_argument("--max-attacks", type=int, default=400)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    samples = _build_samples(args.ext, args.limit)
    if not samples:
        raise SystemExit("нет данных: укажите --ext на каталог со склонированными бенчмарками")
    defense = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))
    rep = run_retrieval_experiment(samples, defense, k=args.k, max_attacks=args.max_attacks)
    print(rep.summary())
    print("\nПо источникам (Hit@k | ASR без фильтра -> с фильтром):")
    for src, m in rep.by_source.items():
        print(f"  {src:22} hit={m['hit_at_k']:.2f}  {m['asr_no_filter']:.2f} -> {m['asr_filter']:.2f}  (n={m['n']})")
    if args.out:
        json.dump(rep.to_dict(), open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
