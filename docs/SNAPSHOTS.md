# Снимки результатов (JSON): откуда берутся, что в них, как читать

Снимок — это файл с результатами эксперимента, сохранённый в `docs/`. Его делает **наш код**, а не
бенчмарк. Этот документ объясняет каждый снимок простым языком.

## Какой код что делает

| Снимок | Чем создаётся (команда) | Код | Нужен ли наш фильтр/стенд |
|---|---|---|---|
| `attack_success.json` | `python scripts/analyze_recorded_runs.py --ext ./ext --out docs/attack_success.json` | `scripts/analyze_recorded_runs.py` | **нет** — считает чужие готовые прогоны |
| `results_indistribution.json` | `python -m ctxauth eval --ext ./ext --out docs/results_indistribution.json` | `ctxauth/cli.py` + `ctxauth/eval/harness.py` | да, фильтр |
| `results_generalization.json` | `python scripts/experiment_generalization.py --ext ./ext --out docs/results_generalization.json` | `scripts/experiment_generalization.py` + `ctxauth/eval/train.py` | да, фильтр |
| `endtoend_results.json` | `python scripts/experiment_endtoend.py --ext ./ext --out docs/endtoend_results.json` | `scripts/experiment_endtoend.py` + `ctxauth/eval/endtoend.py` | да, **весь стенд** |
| `retrieval_results.json` | `python scripts/experiment_retrieval.py --ext ./ext --out docs/retrieval_results.json` | `scripts/experiment_retrieval.py` + `ctxauth/eval/retrieval_exp.py` | да, стенд с **реальным поиском** (эксперимент Б: Hit@k) |
| `robustness.json` | `python scripts/experiment_robustness.py --ext ./ext --out docs/robustness.json` | `scripts/experiment_robustness.py` | да, фильтр (перефразирование и позиция вставки) |

`./ext` — папка со склонированными бенчмарками. Снимки уже лежат в репозитории; перезапуск нужен,
только если что-то поменяли в методе.

---

## 1. `attack_success.json` — уязвимость моделей БЕЗ нашего фильтра

**Самый важный для вопроса «насколько модели уязвимы сами по себе».** Наш фильтр и стенд НЕ
участвуют: скрипт только читает записанные прогоны AgentDojo и TaskTracker и считает успешность атак.

Как получить:
```bash
python scripts/analyze_recorded_runs.py --ext ./ext --out docs/attack_success.json
```

Что внутри:
```
{
  "agentdojo": {
    "by_config": {            # по каждой конфигурации модели/защиты
      "Meta-SecAlign-70B": {"asr_targeted": 0.017, "n_targeted": 2847, "asr_dos": null, "n_dos": 0}
    },
    "by_attack_gpt4o": {      # для GPT-4o — успешность по типам атак
      "important_instructions": 0.477
    },
    "defenses": { ... }       # сравнение «базовая модель → модель с защитой»
  },
  "tasktracker": {
    "llama3_8b": {"n": 31134, "asr_executed": 0.227, "rejected": 0.241, "not_detected": 0.532}
  }
}
```

Как читать:
- `asr_targeted` — доля успешных целевых атак (0.017 = 1,7 % успеха, модель очень устойчива).
- `n_targeted` — на скольких прогонах посчитано.
- `by_attack_gpt4o` — `0.477` значит эта атака срабатывает в 47,7 % случаев.
- TaskTracker: `asr_executed` — выполнено, `rejected` — модель отказалась, `not_detected` —
  **не заметила** инъекцию (0.532 = 53 %).

---

## 2. `results_indistribution.json` — качество нашего метода

Наш фильтр прогоняется по всем размеченным примерам. Три защиты: `no_filter`, `keyword`, `ctxauth`
(наш метод).

Что внутри (для каждой защиты):
```
"ctxauth": {
  "n": 2088,                       # сколько примеров
  "detection": {"overall": {
     "tp": 269, "fp": 42, "tn": 1002, "fn": 775,
     "precision": 0.865, "recall": 0.258, "f1": 0.397, "fpr": 0.040
  }},
  "asr_before": 1.0, "asr_after": 0.74,     # успешность атак до/после фильтра
  "removed_context_ratio": 0.025,           # доля зря удалённого чистого текста
  "by_permission": { ... }, "by_technique": { ... }, "by_source": { ... }
}
```

Как читать:
- `tp` — пойманные атаки, `fp` — зря заблокированные чистые, `tn` — верно пропущенные чистые,
  `fn` — пропущенные атаки.
- `precision` — из заблокированного какая доля реально атаки (0.865 = 87 %).
- `recall` — какую долю всех атак поймали (0.258 = 26 %).
- `fpr` — доля чистых, зря задетых (0.040 = 4 %).
- `asr_after` — успешность атак после фильтра (чем меньше, тем лучше).
- `by_permission` / `by_technique` / `by_source` — те же метрики в разрезе по виду влияния,
  технике и бенчмарку.

---

## 3. `results_generalization.json` — переносимость между бенчмарками

«Обучили на одних наборах, проверили на отложенном». По каждому отложенному набору (piarena / sep /
bipia) — метрики всех защит.
```
"piarena": {"train": 900, "test": 600, "ml_labels": [...],
  "defenses": {
    "rules":      {"precision":0.79,"recall":0.44,"f1":..,"fpr":0.12,"asr_after":..,"removed_clean":0.028},
    "binary_clf": {"precision":0.51,"recall":0.98,"fpr":0.96,"removed_clean":0.97}
}}
```
Главное видно сразу: у обучаемого детектора `fpr`=0.96 и `removed_clean`=0.97 — на незнакомом наборе
он блокирует почти всё. У нашего метода `removed_clean` маленький — переносится устойчиво.

---

## 4. `endtoend_results.json` — сквозной прогон через весь стенд

Атаки идут через весь стенд (поиск → фильтр → модель → инструменты → постобработка) с фильтром и без.
```
{
  "llm": "sim",
  "asr_no_filter": 0.91, "asr_filter": 0.68, "asr_reduction": 0.25,
  "tool_calls_no_filter": 305, "tool_calls_filter": 265,
  "clean_blocked_rate": 0.047, "clean_answer_preserved": 0.964,
  "by_permission": {"disclosure": {"n":37,"asr_no_filter":1.0,"asr_filter":0.38}, ...}
}
```
Как читать:
- `asr_no_filter` / `asr_filter` — успешность атак без фильтра и с ним (0.91 → 0.68).
- `tool_calls_*` — сколько раз модель вызвала внешний инструмент (фильтр их уменьшает).
- `clean_blocked_rate` — доля чистых фрагментов, зря задетых (0.047).
- `clean_answer_preserved` — доля чистых ответов, не изменившихся (0.964).

---

## Можно ли получить результаты без нашего стенда

- **Уязвимость моделей (без фильтра)** — да: `attack_success.json` считается по записанным прогонам
  AgentDojo/TaskTracker, наш стенд не нужен.
- **У самих бенчмарков есть свои запускалки** (официальные скрипты PIArena, BIPIA, AgentDojo): они
  сами атакуют модель и выдают результат — но им нужна **работающая модель** (API или GPU) и это их
  конвейер, не наш стенд.
- **Качество нашего метода** без нашего кода получить нельзя — его считает только наш фильтр/стенд.
