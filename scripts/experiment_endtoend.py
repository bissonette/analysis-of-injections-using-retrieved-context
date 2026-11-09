#!/usr/bin/env python3
"""Сквозной прогон атак через стенд с фильтром и без, с анализом.

По умолчанию — на «наихудшей» модели-симуляторе (верхняя оценка ASR). Для прогона на реальной
локальной модели: --backend ollama --model qwen2.5:7b-instruct --base-url http://localhost:11434/v1

Запуск:  PYTHONPATH=. python scripts/experiment_endtoend.py --ext ./ext --out docs/endtoend_results.json
"""
from __future__ import annotations

import argparse
import json


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
    from ctxauth.cli import _build_samples
    from ctxauth.eval.endtoend import run_endtoend
    from ctxauth.rag.llm import make_llm

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--limit", type=int, default=150)
    ap.add_argument("--mode", default="rules", choices=["rules", "gated", "max", "ml"])
    ap.add_argument("--backend", default="sim", help="sim | ollama | openai-compatible")
    ap.add_argument("--model", default=None)
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    samples = _build_samples(args.ext, args.limit)
    if not samples:
        raise SystemExit("нет данных: укажите --ext на каталог со склонированными бенчмарками")

    analyzer = AuthorityAnalyzer(mode="rules") if args.mode == "rules" else None
    if analyzer is None:
        from ctxauth.eval.train import split_by_source, train_authority_scorer
        tr, _ = split_by_source(samples, {"__none__"})  # обучаем на всех (быстрый апример; для
        ml = train_authority_scorer(samples)            # честной оценки используйте holdout)
        analyzer = AuthorityAnalyzer(mode=args.mode, ml=ml)
    defense = ContextAuthorityController(analyzer)

    llm = None
    if args.backend != "sim":
        cfg = {"backend": args.backend, "model": args.model, "base_url": args.base_url}
        llm = make_llm(cfg)

    r = run_endtoend(samples, defense, llm=llm)
    print(r.summary())
    print("\nПо видам влияния (ASR без фильтра -> с фильтром):")
    for p, m in r.by_permission.items():
        print(f"  {p:14} {m['asr_no_filter']:.2f} -> {m['asr_filter']:.2f}   (n={m['n']})")
    if args.out:
        out = {k: getattr(r, k) for k in ("llm", "n_attacks", "n_clean", "asr_no_filter",
               "asr_filter", "tool_calls_no_filter", "tool_calls_filter", "clean_blocked_rate",
               "clean_answer_preserved", "by_permission")}
        out["asr_reduction"] = round(r.asr_reduction, 3)
        json.dump(out, open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
