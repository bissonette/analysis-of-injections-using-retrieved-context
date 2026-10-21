"""Командная строка проекта.

  python -m ctxauth demo                       — один запрос через конвейер (офлайн-LLM)
  python -m ctxauth eval  --ext /path/to/ext   — прогон защит по бенчмаркам, метрики в JSON
  python -m ctxauth fpr                         — ложные срабатывания на встроенном корпусе
  python -m ctxauth train-clf --ext ... --out model.pkl   — обучить бинарный детектор
"""
from __future__ import annotations

import argparse
import json
import sys


def _build_samples(ext: str, limit: int):
    from .data.loaders import load_bipia, load_piarena, load_sep
    s = []
    for f in ("nq_rag", "msmarco_rag", "hotpotqa_rag"):
        try:
            s += load_piarena(f"{ext}/PIArena/datasets/{f}.json", intent="qa")
        except FileNotFoundError:
            pass
    for path, fn in [(f"{ext}/Should-It-Be-Executed-Or-Processed/SEP_dataset/SEP_dataset.json",
                      lambda p: load_sep(p, limit=limit)),
                     (f"{ext}/BIPIA", lambda p: load_bipia(p, task="email", limit=limit))]:
        try:
            s += fn(path)
        except FileNotFoundError:
            pass
    return s


def cmd_demo(args):
    from .authority import AuthorityAnalyzer, ContextAuthorityController
    from .data.builtin_corpus import builtin_documents
    from .rag.orchestrator import Orchestrator
    k8 = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))
    orch = Orchestrator.from_documents(builtin_documents(), defense=k8, spotlight=args.spotlight)
    res = orch.answer(args.query)
    print("INTENT:", res.filter_result.policy.intent)
    for d in res.filter_result.decisions:
        print(f"  {d.chunk.chunk_id:16} {d.action.value:9} {d.profile.as_codes()}")
    print("\nANSWER:\n", res.answer)
    print("\nTOOL CALLS:", [c.name for c in res.tool_calls], "| blocked urls:", res.post.blocked_urls)


def cmd_eval(args):
    from .authority import AuthorityAnalyzer, ContextAuthorityController
    from .baselines import BinaryChunkDetector, KeywordDetector, NoFilterDefense
    from .eval import evaluate_defense
    from .eval.train import split_by_source, train_binary_detector
    samples = _build_samples(args.ext, args.limit)
    if not samples:
        print("нет данных: укажите --ext на каталог со склонированными бенчмарками", file=sys.stderr)
        sys.exit(2)
    defenses = [NoFilterDefense(), KeywordDetector(),
                ContextAuthorityController(AuthorityAnalyzer(mode="rules"))]
    if args.holdout:
        # честная кросс-бенчмарковая проверка: обучаем бинарный детектор на остальных
        # источниках и тестируем на отложенном (--holdout, напр. "sep" или "bipia").
        test_src = set(args.holdout.split(","))
        train, test = split_by_source(samples, test_src)
        det = train_binary_detector(train)
        print(f"# holdout={sorted(test_src)}: train={len(train)} test={len(test)}")
        for d in defenses + [det]:
            print("  OOD " + evaluate_defense(d, test).summary())
        print("# (binary_clf выше — обучен БЕЗ отложенного источника: оценка обобщения)")
        samples = test
    if args.clf:
        defenses.append(BinaryChunkDetector.load(args.clf))
    reports = {}
    for d in defenses:
        rep = evaluate_defense(d, samples)
        print(rep.summary())
        reports[rep.defense] = rep.to_dict()
    if args.out:
        json.dump(reports, open(args.out, "w"), ensure_ascii=False, indent=2)
        print("отчёт:", args.out)


def cmd_fpr(args):
    from .authority import AuthorityAnalyzer, ContextAuthorityController
    from .data.loaders import load_builtin_clean
    from .eval import evaluate_defense
    k8 = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))
    rep = evaluate_defense(k8, load_builtin_clean())
    print(rep.summary())
    for cat, m in sorted(rep.by_source.items()):
        pass


def cmd_train(args):
    from .data.loaders import load_bipia, load_piarena, load_sep
    from .eval.train import train_binary_detector
    samples = _build_samples(args.ext, args.limit)
    det = train_binary_detector(samples)
    det.save(args.out)
    print(f"обучен бинарный детектор на {len(samples)} примерах -> {args.out}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="ctxauth")
    sub = ap.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo"); d.add_argument("--query", default="Briefly summarize how to reset a corporate password")
    d.add_argument("--spotlight", action="store_true"); d.set_defaults(func=cmd_demo)
    e = sub.add_parser("eval"); e.add_argument("--ext", required=True); e.add_argument("--limit", type=int, default=200)
    e.add_argument("--clf", default=None); e.add_argument("--out", default=None)
    e.add_argument("--holdout", default=None, help="источник(и) для кросс-бенчмарковой проверки, напр. sep или bipia")
    e.set_defaults(func=cmd_eval)
    f = sub.add_parser("fpr"); f.set_defaults(func=cmd_fpr)
    t = sub.add_parser("train-clf"); t.add_argument("--ext", required=True); t.add_argument("--limit", type=int, default=400)
    t.add_argument("--out", default="model.pkl"); t.set_defaults(func=cmd_train)
    args = ap.parse_args(argv)
    args.func(args)


if __name__ == "__main__":
    main()
