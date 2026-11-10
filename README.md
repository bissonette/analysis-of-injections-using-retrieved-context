# ctxauth — контроль разрешений retrieved-контекста в RAG-системах

Вместо бинарного детектирования prompt injection метод определяет, **какие виды влияния на ответ
модели имеет право оказывать каждый retrieved-фрагмент**, и пропускает / очищает / блокирует
фрагмент до передачи в LLM. Виды влияния: содержание ответа, задача модели, инструкции модели,
раскрытие информации, действия/инструменты, форма ответа и внешний канал. Набор разрешённых
видов зависит от запроса пользователя.

## Структура

| Путь | Что внутри |
|---|---|
| `ctxauth/types.py`, `ctxauth/taxonomy.py` | виды влияния, техники инъекций, список модулей |
| `ctxauth/rag/` | RAG-стенд: разбиение, индекс, ретривер, промпт, LLM, инструменты, постобработка, журнал |
| `ctxauth/authority/` | **основной метод**: `intent.py` (запрос → что разрешено), `rules.py` + `analyzer.py` (на что претендует предложение), `ml.py` (обучаемый скорер), `controller.py` (PASS / SANITIZE / BLOCK) |
| `ctxauth/data/builtin_corpus.py` | 35 безопасных документов, из них 19 «трудных» для оценки ложных срабатываний |

## Установка и запуск

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
```

```python
from ctxauth.data.builtin_corpus import builtin_documents
from ctxauth.rag.chunking import chunk_document
from ctxauth.rag.embed import make_embedder
from ctxauth.rag.index import VectorIndex
from ctxauth.rag.retriever import Retriever
from ctxauth.rag.prompts import SYSTEM_PROMPT, build_user_message
from ctxauth.rag.tools import ToolRegistrar
from ctxauth.rag.llm import OpenAICompatibleLLM, SimulatedLLM
from ctxauth.rag.postprocess import postprocess
from ctxauth.authority import AuthorityAnalyzer, ContextAuthorityController

chunks = [c for d in builtin_documents() for c in chunk_document(d, max_words=60)]
retriever = Retriever(VectorIndex(make_embedder("tfidf")).build(chunks), k=5)
k8 = ContextAuthorityController(AuthorityAnalyzer(mode="rules"))
tools = ToolRegistrar()
llm = SimulatedLLM()  # реальная модель: OpenAICompatibleLLM(model="qwen2.5:7b-instruct", base_url="http://localhost:11434/v1")

q = "Briefly summarize how to reset a corporate password"
res = k8.filter(q, retriever.retrieve(q))
for d in res.decisions:
    print(d.chunk.chunk_id, d.action.value, d.profile.as_codes(),
          [(v.permission.code, v.reason) for v in d.violations])
kept = res.kept_chunks
out = llm.generate(SYSTEM_PROMPT, build_user_message(q, kept, tools.specs),
                   query=q, chunks=kept, tools=tools.specs)
print(postprocess(out.text, res.policy.domain_allowlist).text, out.tool_calls)
```

Параметры (`ControllerConfig`): `request_dependent=False` — не зависящий от запроса набор разрешений (абляция),
`sanitize=False` — блокировать фрагмент целиком, `thresholds` — пороги по полномочиям;
`AuthorityAnalyzer(mode="rules"|"ml"|"max")`.

## Результаты (воспроизводятся на скачанных бенчмарках)

Детектирование без запуска LLM, 2088 примеров (PIArena + SEP + BIPIA + BIPIA-обфускация +
InjecAgent + Raccoon):

| Защита | Precision | Recall | F1 | FPR | ASR до→после | удалено чистого |
|---|---|---|---|---|---|---|
| без фильтра | — | — | — | 0.00 | 1.00→1.00 | 0.000 |
| по ключевым словам | 0.89 | 0.12 | 0.21 | 0.014 | 1.00→0.88 | 0.052 |
| **контроль полномочий (правила)** | **0.90** | **0.33** | **0.49** | **0.035** | **1.00→0.69** | **0.018** |

Сквозной прогон через весь стенд (с фильтром и без, «наихудшая» модель): ASR **1.00→0.69**,
вызовы внешних инструментов 305→263, ложные на чистых 0.041, ответы сохранены 0.97
(`docs/endtoend_analysis.md`).

### Переносимость между бенчмарками (главный вывод)

Обучение на одних наборах, проверка на отложенном (воспроизводится
`scripts/experiment_generalization.py`, снимок — `docs/results_generalization.json`):

| Отложенный набор | Защита | Precision | Recall | FPR | удалено чистого |
|---|---|---|---|---|---|
| PIArena | контроль полномочий (правила) | 0.81 | 0.44 | **0.10** | **0.020** |
| PIArena | правила + ML (gated) | 0.69 | 0.53 | 0.23 | 0.029 |
| PIArena | обучаемый бинарный детектор | 0.51 | 0.98 | **0.96** | **0.97** |

Вывод: обучаемый детектор на незнакомом наборе **ломается** — блокирует почти весь контекст
(FPR 0.96, удаляет 97 % чистого текста). Правиловое ядро метода переносится устойчиво
(удаляет 3 % чистого), а обучаемая надстройка `gated` расширяет границу recall ценой роста FPR —
это настраиваемый компромисс (`gate`). Скрытая подмена задачи (SEP) после доработки детектора
«не по теме команда» ловится заметно лучше: на отложенном SEP правила дают P=0.94, R=0.45, FPR=0.03.
Это согласуется с известным наблюдением о плохой переносимости детекторов (напр. авторы PIArena).
Снимки метрик: `docs/results_indistribution.json`, `docs/results_generalization.json`.

Ложные срабатывания на встроенном «трудном» корпусе (мануалы, статьи о безопасности, регламенты):
FPR 0.051.

Документация: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md), [docs/attack_analysis.md](docs/attack_analysis.md) — анализ успешности атак, [docs/existing_solutions.md](docs/existing_solutions.md) — обзор решений, [docs/EXPLAINER.md](docs/EXPLAINER.md) — пояснения простым языком, [docs/endtoend_analysis.md](docs/endtoend_analysis.md) — сквозной прогон, [docs/REPORT_FOR_ADVISOR.md](docs/REPORT_FOR_ADVISOR.md) — отчёт, [docs/benchmark_quotes.md](docs/benchmark_quotes.md) — цитаты из статей, [docs/SNAPSHOTS.md](docs/SNAPSHOTS.md) — про JSON-снимки результатов.

## Статус

Сделано: RAG-стенд, основной метод (правила + обучаемый скорер), встроенный корпус.

Остаточные ложные срабатывания на «трудных» безопасных документах — около 3 % фрагментов
(пограничные случаи: инструкции администратору, где действие и описание действия неразличимы).

Не сделано: веб-интерфейс, прогон атак через реальную LLM,
загрузчики дополнительных корпусов. Прогоны атак выполняются официальными
скриптами бенчмарков (BIPIA, AgentDojo, PIArena, SEP) с локальной моделью.

Связь «техника → вид влияния» в `taxonomy.py` рабочая — при необходимости уточняется.

## Командная строка

```bash
python -m ctxauth demo                                  # один запрос через стенд
python -m ctxauth fpr                                   # ложные срабатывания на встроенном корпусе
python -m ctxauth eval --ext ./ext --limit 200 --out docs/results.json
python -m ctxauth eval --ext ./ext --holdout piarena    # кросс-бенчмарковая проверка обобщения
python -m ctxauth train-clf --ext ./ext --out model.pkl # обучить бинарный детектор-baseline
PYTHONPATH=. python scripts/experiment_generalization.py --ext ./ext --out docs/results_generalization.json
python -m pytest -q                                     # тесты
```
