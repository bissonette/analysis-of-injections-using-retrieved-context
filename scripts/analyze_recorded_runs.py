#!/usr/bin/env python3
"""Анализ УСПЕШНОСТИ АТАК по уже записанным прогонам реальных моделей.

Отвечает на вопрос «насколько атаки успешны и как проявляется уязвимое поведение»
БЕЗ запуска моделей — на готовых результатах двух бенчмарков:

* AgentDojo (ext/agentdojo/runs/<конфигурация>/<набор>/<задача>/<атака>/<инъекция>.json):
  поле `security` — исполнена ли инъекция (True = атака УСПЕШНА). attack_type="none" —
  прогон без инъекции (базовый), исключается. Атаки *_dos — отказ в обслуживании.
  ASR(конфигурация, тип атаки) = доля security==True.

* TaskTracker (ext/TaskTracker/.../dataset_sampled/<модель>/..._verifier.json):
  метка исхода на каждый отравленный пример: EXECUTED (инъекция выполнена),
  REJECTED (модель заметила и отказалась), NOT DETECTED (модель не заметила вставку).
  ASR(модель) = доля EXECUTED; NOT DETECTED — признак скрытой уязвимости.

Запуск:  python scripts/analyze_recorded_runs.py --ext ./ext --out docs/attack_success.json
"""
from __future__ import annotations

import argparse
import collections
import glob
import json
import os


def _is_true(v) -> bool:
    return v is True or v == "True"


# --------------------------------------------------------------------------- AgentDojo
def analyze_agentdojo(ext: str) -> dict:
    root = os.path.join(ext, "agentdojo", "runs")
    report: dict = {"by_config": {}, "by_attack_gpt4o": {}, "defenses": {}}
    if not os.path.isdir(root):
        return report
    configs = sorted(os.listdir(root))
    for cfg in configs:
        n = s = 0
        by_attack = collections.Counter()
        tot_attack = collections.Counter()
        dos_n = dos_s = 0
        for p in glob.glob(os.path.join(root, cfg, "*", "*", "*", "*.json")):
            attack = p.split(os.sep)[-2]
            if attack == "none":
                continue
            try:
                d = json.load(open(p))
            except (json.JSONDecodeError, OSError):
                continue
            if d.get("injection_task_id") in (None, "None"):
                continue
            ok = _is_true(d.get("security"))
            if attack.endswith("dos") or attack == "dos":
                dos_n += 1
                dos_s += int(ok)
            else:
                n += 1
                s += int(ok)
            tot_attack[attack] += 1
            by_attack[attack] += int(ok)
        if n:
            report["by_config"][cfg] = {
                "asr_targeted": round(s / n, 3),
                "n_targeted": n,
                "asr_dos": round(dos_s / dos_n, 3) if dos_n else None,
                "n_dos": dos_n,
            }
    base = "gpt-4o-2024-05-13"
    if base in configs:
        acc: dict = {}
        for p in glob.glob(os.path.join(root, base, "*", "*", "*", "*.json")):
            attack = p.split(os.sep)[-2]
            if attack == "none":
                continue
            try:
                d = json.load(open(p))
            except (json.JSONDecodeError, OSError):
                continue
            if d.get("injection_task_id") in (None, "None"):
                continue
            a = acc.setdefault(attack, [0, 0])
            a[0] += int(_is_true(d.get("security")))
            a[1] += 1
        report["by_attack_gpt4o"] = {a: round(v[0] / v[1], 3) for a, v in sorted(acc.items(), key=lambda x: -x[1][0] / x[1][1])}
    # защиты: известные суффиксы конфигураций «<base>-<defense>» сравниваем с базовой моделью
    defense_suffixes = ("repeat_user_prompt", "spotlighting_with_delimiting",
                        "tool_filter", "transformers_pi_detector")
    for cfg, st in report["by_config"].items():
        for suf in defense_suffixes:
            if cfg.endswith("-" + suf):
                base = cfg[: -len(suf) - 1]
                if base in report["by_config"]:
                    report["defenses"][cfg] = {
                        "base": base, "defense": suf,
                        "asr_base": report["by_config"][base]["asr_targeted"],
                        "asr_defended": st["asr_targeted"],
                    }
                break
    return report


# --------------------------------------------------------------------------- TaskTracker
def analyze_tasktracker(ext: str) -> dict:
    root = os.path.join(ext, "TaskTracker", "task_tracker", "dataset_creation", "dataset_sampled")
    out: dict = {}
    for d in sorted(glob.glob(os.path.join(root, "*"))):
        vf = glob.glob(os.path.join(d, "*verifier.json"))
        if not vf:
            continue
        model = os.path.basename(d).replace("_responses", "").replace("_response", "")
        labels = collections.Counter()
        data = json.load(open(vf[0]))
        for v in data.values():
            labels[str(v.get("short", "")).upper().strip()] += 1
        total = sum(labels.values())
        executed = labels.get("EXECUTED", 0)
        rejected = labels.get("REJECTED", 0)
        notdet = labels.get("NOT DETECTED", 0)
        if total:
            out[model] = {
                "n": total,
                "asr_executed": round(executed / total, 3),
                "rejected": round(rejected / total, 3),
                "not_detected": round(notdet / total, 3),
            }
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--ext", required=True)
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    ad = analyze_agentdojo(args.ext)
    tt = analyze_tasktracker(args.ext)

    print("=== AgentDojo: ASR по типам атак (gpt-4o-2024-05-13) ===")
    for a, v in ad["by_attack_gpt4o"].items():
        print(f"  {a:42} ASR={v:.2f}")
    print("\n=== AgentDojo: уязвимость моделей (целевые атаки, по убыванию ASR) ===")
    base_cfgs = {c: s for c, s in ad["by_config"].items() if c not in ad["defenses"]}
    for c, s in sorted(base_cfgs.items(), key=lambda x: -x[1]["asr_targeted"])[:18]:
        print(f"  {c:42} ASR={s['asr_targeted']:.2f}  DoS={s['asr_dos']}  n={s['n_targeted']}")
    if ad["defenses"]:
        print("\n=== AgentDojo: эффект защит (gpt-4o) ===")
        for c, s in ad["defenses"].items():
            print(f"  {c:48} {s['asr_base']:.2f} -> {s['asr_defended']:.2f}")
    print("\n=== TaskTracker: исход инъекций по моделям ===")
    for m, v in tt.items():
        print(f"  {m:28} EXECUTED(ASR)={v['asr_executed']:.2f}  REJECTED={v['rejected']:.2f}  NOT_DETECTED={v['not_detected']:.2f}  n={v['n']}")

    if args.out:
        json.dump({"agentdojo": ad, "tasktracker": tt}, open(args.out, "w"), ensure_ascii=False, indent=2)
        print("\nотчёт:", args.out)


if __name__ == "__main__":
    main()
