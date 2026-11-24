#!/usr/bin/env python3
"""Сводка и парное сравнение уже сохранённых журналов Colab."""
from __future__ import annotations

import argparse
import hashlib
import json
from dataclasses import dataclass
from pathlib import Path


IDENTITY_FIELDS = ("kind", "source", "permission", "criterion", "markers")
ATTACK_FIELDS = ("success_no_filter", "success_filter")
CLEAN_FIELDS = ("touched", "preserved")
CONDITIONS = ("backend", "model", "max_chars", "max_tokens", "num_ctx", "judge")


@dataclass
class Run:
    records: dict[str, dict]
    conditions: dict | None
    sha256: str
    duplicate_rows: dict[str, int]
    error_rows: int
    unresolved_errors: int


def load_run(path: Path) -> Run:
    records: dict[str, dict] = {}
    failed = set()
    duplicates = {"attack": 0, "clean": 0}
    error_rows = 0
    digest = hashlib.sha256()
    with path.open("rb") as journal:
        for line_number, raw in enumerate(journal, 1):
            digest.update(raw)
            if not raw.strip():
                continue
            try:
                row = json.loads(raw)
                key = row["key"]
                kind = row["kind"]
                if not isinstance(key, str) or not key or kind not in duplicates:
                    raise ValueError("некорректный ключ или тип примера")
                if row.get("error"):
                    failed.add(key)
                    error_rows += 1
                    continue
                fields = ATTACK_FIELDS if kind == "attack" else CLEAN_FIELDS
                if not all(isinstance(row.get(field), bool) for field in fields):
                    raise ValueError("отсутствует или некорректна метка результата")
                if not isinstance(row.get("source"), str) or not isinstance(row.get("criterion"), str):
                    raise ValueError("отсутствует источник или критерий успеха")
                if kind == "attack" and (
                    not isinstance(row.get("permission"), str)
                    or row.get("action") not in {"pass", "sanitize", "block"}
                ):
                    raise ValueError("отсутствует вид влияния или решение фильтра")
                record = {field: row.get(field) for field in (*IDENTITY_FIELDS, "action", *fields)}
                if key in records:
                    if records[key] != record:
                        raise ValueError(f"повторный ключ с разными результатами: {key}")
                    duplicates[kind] += 1
                else:
                    records[key] = record
            except (KeyError, TypeError, ValueError) as exc:
                raise ValueError(f"{path.name}, строка {line_number}: {exc}") from exc
    if not records:
        raise ValueError(f"{path.name}: нужны записи с результатами")

    summary_path = path.with_suffix(".json")
    conditions = None
    if summary_path.is_file():
        summary = json.loads(summary_path.read_text(encoding="utf-8-sig"))
        config = summary.get("config") if isinstance(summary, dict) else None
        if not isinstance(config, dict) or any(field not in config for field in CONDITIONS):
            raise ValueError(f"{summary_path.name}: отсутствуют параметры прогона")
        conditions = {field: config[field] for field in CONDITIONS}
    return Run(records, conditions, digest.hexdigest(), duplicates, error_rows, len(failed - records.keys()))


def paired_counts(before: list[bool], after: list[bool]) -> dict:
    n = len(before)
    if n != len(after):
        raise ValueError("результаты должны быть парными")
    return {
        "n": n,
        "before": sum(before),
        "after": sum(after),
        "removed": sum(a and not b for a, b in zip(before, after)),
        "added": sum(not a and b for a, b in zip(before, after)),
        "delta_percentage_points": 100 * (sum(after) - sum(before)) / n if n else None,
    }


def attack_stats(rows: list[dict]) -> dict:
    counts = paired_counts([r["success_no_filter"] for r in rows], [r["success_filter"] for r in rows])
    counts["passed_successes"] = sum(r["success_filter"] and r["action"] == "pass" for r in rows)
    return counts


def groups(rows: list[dict], field: str) -> dict[str, list[dict]]:
    grouped: dict[str, list[dict]] = {}
    for row in rows:
        grouped.setdefault(row[field], []).append(row)
    return dict(sorted(grouped.items()))


def summarize(run: Run) -> dict:
    attack = [row for row in run.records.values() if row["kind"] == "attack"]
    clean = [row for row in run.records.values() if row["kind"] == "clean"]
    return {
        "journal_sha256": run.sha256,
        "recorded_conditions": run.conditions,
        "duplicate_rows": run.duplicate_rows,
        "error_rows": run.error_rows,
        "unresolved_errors": run.unresolved_errors,
        "attacks": attack_stats(attack),
        "clean": {"n": len(clean), "touched": sum(r["touched"] for r in clean),
                  "verbatim_preserved": sum(r["preserved"] for r in clean)},
        "by_permission": {label: attack_stats(rows) for label, rows in groups(attack, "permission").items()},
        "by_source": {label: attack_stats(rows) for label, rows in groups(attack, "source").items()},
    }


def compare(previous: Run, candidate: Run) -> dict:
    if previous.conditions is None or candidate.conditions is None:
        raise ValueError("Для сравнения нужны обе сводки .json с настройками прогонов")
    if previous.conditions != candidate.conditions:
        differing = [field for field in CONDITIONS if previous.conditions[field] != candidate.conditions[field]]
        raise ValueError(f"Различаются условия прогонов: {', '.join(differing)}")
    if previous.unresolved_errors or candidate.unresolved_errors:
        raise ValueError("Сравнение требует журналов без примеров с незавершённой обработкой")

    old, new = previous.records, candidate.records
    if old.keys() != new.keys():
        raise ValueError(f"Выборки различаются: только в прежнем журнале {len(old.keys() - new.keys())}, "
                         f"только в новом {len(new.keys() - old.keys())}")
    for key, row in old.items():
        if any(row[field] != new[key][field] for field in IDENTITY_FIELDS):
            raise ValueError(f"Источник, класс или критерий оценки изменился для {key}")

    attack = [key for key, row in old.items() if row["kind"] == "attack"]
    clean = [key for key, row in old.items() if row["kind"] == "clean"]
    if not attack or not clean:
        raise ValueError("Для сравнения нужны примеры с инъекциями и чистые примеры")

    def pair(keys: list[str], field: str) -> dict:
        return paired_counts([old[k][field] for k in keys], [new[k][field] for k in keys])

    def grouped_stats(field: str) -> dict:
        keyed = groups([{**old[key], "key": key} for key in attack], field)
        return {label: pair([row["key"] for row in rows], "success_filter") for label, rows in keyed.items()}

    return {
        "attacks_with_filter": pair(attack, "success_filter"),
        "attacks_without_filter": pair(attack, "success_no_filter"),
        "clean_touched": pair(clean, "touched"),
        "clean_verbatim_preserved": pair(clean, "preserved"),
        "by_permission": grouped_stats("permission"),
        "by_source": grouped_stats("source"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path, help="исходный журнал .jsonl")
    parser.add_argument("--candidate", type=Path, help="журнал доработанного фильтра")
    parser.add_argument("--out", type=Path, help="путь для нового отчёта .json")
    args = parser.parse_args()
    try:
        previous = load_run(args.previous)
        report = {"previous": summarize(previous)}
        if args.candidate is not None:
            candidate = load_run(args.candidate)
            report.update({"candidate": summarize(candidate), "comparison": compare(previous, candidate)})
        result = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
        if args.out is None:
            print(result, end="")
        else:
            with args.out.open("x", encoding="utf-8") as output:
                output.write(result)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"{exc}\n")


if __name__ == "__main__":
    main()
