#!/usr/bin/env python3
"""Устойчивость метода к перефразированию и позиции вставки.

Перефразирование НЕ генерируется — используются готовые вариации из самих бенчмарков:
у каждой категории (цели) атаки в BIPIA/PIArena много разных формулировок одной и той же цели.
Метрика устойчивости к перефразированию: для каждой цели — доля её формулировок, которые метод
ловит; затем распределение целей по стабильности (ловится стабильно / частично / слабо).

Позиция вставки: Chen et al. вставляет ту же инъекцию в начало/середину/конец контекста —
считаем полноту по позициям.

Запуск: PYTHONPATH=. python scripts/experiment_robustness.py --ext ./ext --out docs/robustness.json
"""
from __future__ import annotations

import argparse
import collections
import json


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
    from ctxauth.data.loaders import load_bipia, load_chen, load_piarena, load_raccoon
    from ctxauth.types import Action

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    ext = args.ext

    k8 = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))

    def caught(s) -> bool:
        return k8.filter(s.query, [s.as_chunk()], intent=s.intent).decisions[0].action != Action.PASS

    # --- перефразирование: категория (цель) → разные формулировки --------------------------
    samples = []
    for f in ("nq_rag", "msmarco_rag", "hotpotqa_rag", "squad_v2", "dolly_summarization"):
        try:
            samples += load_piarena(f"{ext}/PIArena/datasets/{f}.json")
        except FileNotFoundError:
            pass
    for t in ("email", "table", "code"):
        try:
            samples += load_bipia(f"{ext}/BIPIA", task=t, limit=300)
        except FileNotFoundError:
            pass
    try:
        samples += load_raccoon(f"{ext}/RaccoonBench")
    except FileNotFoundError:
        pass

    per_goal: dict = collections.defaultdict(lambda: [0, 0])
    for s in samples:
        if not s.is_injected or not s.meta.get("category") or s.meta["category"] == "clean":
            continue
        g = f"{s.source.split('/')[0]}:{s.meta['category']}"
        per_goal[g][1] += 1
        per_goal[g][0] += caught(s)

    goals = {g: {"n_phrasings": n, "recall": round(c / n, 3)} for g, (c, n) in per_goal.items() if n >= 3}
    stable = sum(1 for v in goals.values() if v["recall"] >= 0.8)
    partial = sum(1 for v in goals.values() if 0.2 <= v["recall"] < 0.8)
    weak = sum(1 for v in goals.values() if v["recall"] < 0.2)
    print(f"=== Перефразирование: {len(goals)} целей, формулировок всего "
          f"{sum(v['n_phrasings'] for v in goals.values())} ===")
    print(f"  целей ловится стабильно (recall>=0.8): {stable}")
    print(f"  частично (0.2..0.8): {partial}")
    print(f"  слабо (<0.2): {weak}")
    for g, v in sorted(goals.items(), key=lambda x: -x[1]["recall"]):
        print(f"    {g:45} recall={v['recall']:.2f} (формулировок={v['n_phrasings']})")

    # --- позиция вставки (Chen) --------------------------------------------------------------
    pos_stat: dict = collections.defaultdict(lambda: [0, 0])
    for ds in ("squad", "tri"):
        try:
            chen = load_chen(f"{ext}/indirect-pia-detection", dataset=ds, limit=300)
        except FileNotFoundError:
            continue
        for s in chen:
            if not s.is_injected:
                continue
            p = s.meta["position"]
            pos_stat[p][1] += 1
            pos_stat[p][0] += caught(s)
    print("\n=== Позиция вставки (Chen et al.) ===")
    positions = {p: {"n": n, "recall": round(c / n, 3)} for p, (c, n) in pos_stat.items()}
    for p, v in sorted(positions.items()):
        print(f"  {p:7} recall={v['recall']:.2f} (n={v['n']})")

    if args.out:
        json.dump({"phrasing_goals": goals,
                   "phrasing_summary": {"stable": stable, "partial": partial, "weak": weak},
                   "position": positions}, open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
