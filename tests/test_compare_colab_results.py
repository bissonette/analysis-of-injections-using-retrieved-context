import json
import tempfile
import unittest
from pathlib import Path

from scripts.compare_colab_results import compare, load_run, summarize


SETTINGS = {
    "backend": "test", "model": "example", "max_chars": 1000,
    "max_tokens": 100, "num_ctx": 1024, "judge": False,
}


def attack(key, *, without, with_filter, action="sanitize"):
    return {
        "key": key, "kind": "attack", "source": "fixture", "permission": "task",
        "criterion": "keyword", "markers": [], "action": action,
        "success_no_filter": without, "success_filter": with_filter,
    }


CLEAN = {
    "key": "clean:1", "kind": "clean", "source": "fixture", "criterion": "sim",
    "action": "pass", "touched": False, "preserved": True,
}


class ColabComparisonTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write_run(self, name, rows, **conditions):
        path = self.root / f"{name}.jsonl"
        path.write_text("".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8")
        path.with_suffix(".json").write_text(json.dumps({"config": SETTINGS | conditions}), encoding="utf-8")
        return path

    def test_deduplicates_clean_and_counts_only_unresolved_errors(self):
        first = attack("attack:1", without=True, with_filter=False)
        old_error = {**first, "error": "temporary"}
        path = self.write_run("base", [old_error, first, CLEAN, {**CLEAN, "output_filter": "other text"}])
        stats = summarize(load_run(path))
        self.assertEqual(stats["clean"], {"n": 1, "touched": 0, "verbatim_preserved": 1})
        self.assertEqual(stats["duplicate_rows"]["clean"], 1)
        self.assertEqual((stats["error_rows"], stats["unresolved_errors"]), (1, 0))

    def test_comparison_matches_by_key_and_reports_baseline_drift(self):
        a = attack("attack:1", without=True, with_filter=True)
        b = attack("attack:2", without=False, with_filter=True)
        previous = load_run(self.write_run("base", [a, b, CLEAN]))
        candidate = load_run(self.write_run("new", [
            CLEAN, {**b, "success_no_filter": True}, {**a, "success_filter": False},
        ]))
        result = compare(previous, candidate)
        self.assertEqual(result["attacks_with_filter"]["removed"], 1)
        self.assertEqual(result["attacks_with_filter"]["delta_percentage_points"], -50)
        self.assertEqual(result["by_permission"]["task"]["after"], 1)
        self.assertEqual(result["attacks_without_filter"]["added"], 1)

    def test_rejects_conflicting_repeated_outcomes(self):
        path = self.write_run("conflict", [CLEAN, {**CLEAN, "preserved": False}])
        with self.assertRaisesRegex(ValueError, "повторный ключ"):
            load_run(path)

    def test_rejects_incomparable_runs(self):
        a = attack("attack:1", without=True, with_filter=False)
        previous = load_run(self.write_run("base", [a, CLEAN]))
        for name, rows, conditions, error in [
            ("settings", [a, CLEAN], {"model": "other"}, "условия"),
            ("sample", [{**a, "key": "attack:9"}, CLEAN], {}, "Выборки"),
            ("criterion", [{**a, "criterion": "judge"}, CLEAN], {}, "критерий"),
            ("unfinished", [a, CLEAN, {**a, "key": "attack:9", "error": "failed"}], {}, "незавершённой"),
        ]:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, error):
                compare(previous, load_run(self.write_run(name, rows, **conditions)))
