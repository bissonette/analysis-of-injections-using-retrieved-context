#!/usr/bin/env python3
"""Сквозной прогон атак через стенд с фильтром и без, с анализом.

По умолчанию — на «наихудшей» модели-симуляторе (верхняя оценка ASR). Прогон на реальной
локальной модели (Ollama) — см. docs/LIVE_RUN.md:

  python scripts/experiment_endtoend.py --ext ./ext --backend ollama --model qwen2.5:7b-instruct \
      --out docs/endtoend_real.json

PYTHONPATH задавать не нужно — скрипт сам находит пакет ctxauth.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
try:  # консоль Windows: не падать на символах, которых нет в кодировке консоли
    sys.stdout.reconfigure(errors="replace")
except AttributeError:
    pass


def main():
    from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController
    from ctxauth.cli import _build_samples
    from ctxauth.eval.endtoend import run_endtoend
    from ctxauth.rag.llm import LLMUnavailable, make_llm

    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--limit", type=int, default=150, help="сколько примеров брать из каждого бенчмарка")
    ap.add_argument("--mode", default="rules", choices=["rules", "gated", "max", "ml"])
    ap.add_argument("--backend", default="sim", help="sim | ollama | openai-compatible")
    ap.add_argument("--model", default=None)
    ap.add_argument("--base-url", default="http://localhost:11434/v1")
    ap.add_argument("--timeout", type=float, default=600, help="сек на один ответ модели")
    ap.add_argument("--max-tokens", type=int, default=400, help="макс. длина ответа модели")
    ap.add_argument("--retries", type=int, default=3)
    ap.add_argument("--max-attacks", type=int, default=None,
                    help="сколько атак прогнать (поровну по бенчмаркам); для живой модели по умолчанию 150")
    ap.add_argument("--max-clean", type=int, default=None,
                    help="сколько чистых примеров; для живой модели по умолчанию 50")
    ap.add_argument("--max-chars", type=int, default=None,
                    help="пропускать слишком длинные фрагменты; для живой модели по умолчанию 4000 "
                         "(иначе Ollama может обрезать контекст вместе с инъекцией)")
    ap.add_argument("--judge", action="store_true",
                    help="использовать модель как судью для атак без явного маркера успеха (часть BIPIA)")
    ap.add_argument("--checkpoint", default=None,
                    help="JSONL с результатами по каждому примеру (по умолчанию рядом с --out)")
    ap.add_argument("--fresh", action="store_true", help="не продолжать старый прогон, начать заново")
    ap.add_argument("--preset", choices=["test", "full"], default=None,
                    help="test — пробный (20 атак, 5 чистых, 5–20 мин); "
                         "full — полный объём (все подходящие примеры: ~770 атак, ~930 чистых)")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    live = args.backend != "sim"
    # объём: явные --max-* важнее пресета; без пресета для живой модели — средний объём 150/50
    presets = {"test": (20, 5), "full": (None, None)}
    if args.preset:
        pa, pc = presets[args.preset]
        args.max_attacks = args.max_attacks if args.max_attacks is not None else pa
        args.max_clean = args.max_clean if args.max_clean is not None else pc
    elif live:
        args.max_attacks = args.max_attacks if args.max_attacks is not None else 150
        args.max_clean = args.max_clean if args.max_clean is not None else 50
    if live:
        args.max_chars = args.max_chars if args.max_chars is not None else 4000

    samples = _build_samples(args.ext, args.limit)
    if not samples:
        raise SystemExit("нет данных: укажите --ext на каталог со склонированными бенчмарками")

    analyzer = AuthorityAnalyzer(mode="rules") if args.mode == "rules" else None
    if analyzer is None:
        from ctxauth.eval.train import train_authority_scorer
        ml = train_authority_scorer(samples)  # быстрый вариант; для честной оценки — holdout
        analyzer = AuthorityAnalyzer(mode=args.mode, ml=ml)
    defense = ContextAuthorityController(analyzer)

    llm = None
    if live:
        llm = make_llm({"backend": args.backend, "model": args.model, "base_url": args.base_url,
                        "timeout": args.timeout, "max_tokens": args.max_tokens, "retries": args.retries})
        try:
            print(f"Проверяю сервер {args.base_url} и модель {args.model} …", flush=True)
            llm.check_server()
            print("Загружаю модель в память (первый запрос может занять несколько минут) …", flush=True)
            print(f"  модель готова за {llm.warmup():.0f} с", flush=True)
        except LLMUnavailable as e:
            raise SystemExit(f"\nНЕ УДАЛОСЬ: {e}")

    checkpoint = args.checkpoint
    if checkpoint is None and args.out:
        checkpoint = str(Path(args.out).with_suffix(".jsonl"))
    if checkpoint and args.fresh and Path(checkpoint).exists():
        Path(checkpoint).unlink()
    if checkpoint and Path(checkpoint).exists():
        print(f"Продолжаю прогон из {checkpoint} (готовые примеры пропускаются)", flush=True)

    t0 = time.perf_counter()
    try:
        r = run_endtoend(samples, defense, llm=llm, max_attacks=args.max_attacks,
                         max_clean=args.max_clean, max_chars=args.max_chars, judge=args.judge,
                         checkpoint=checkpoint,
                         progress=(lambda m: print(m, flush=True)) if live else None)
    except RuntimeError as e:
        raise SystemExit(f"\nОСТАНОВЛЕНО: {e}")

    print("\n" + r.summary())
    print(f"запросов к модели: {r.llm_calls}, время: {(time.perf_counter() - t0) / 60:.1f} мин")
    print("\nПо видам влияния (ASR без фильтра -> с фильтром):")
    for p, m in r.by_permission.items():
        print(f"  {p:14} {m['asr_no_filter']:.2f} -> {m['asr_filter']:.2f}   (n={m['n']})")
    print("\nПо бенчмаркам:")
    for src, m in r.by_source.items():
        print(f"  {src:22} {m['asr_no_filter']:.2f} -> {m['asr_filter']:.2f}   (n={m['n']})")
    if args.out:
        out = r.to_dict()
        out["config"] = {k: getattr(args, k) for k in ("backend", "model", "preset", "limit", "max_attacks",
                         "max_clean", "max_chars", "max_tokens", "judge")}
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", encoding="utf-8") as f:
            json.dump(out, f, ensure_ascii=False, indent=2)
        print(f"\nотчёт: {args.out}" + (f"\nподробности по каждому примеру: {checkpoint}" if checkpoint else ""))


if __name__ == "__main__":
    main()
