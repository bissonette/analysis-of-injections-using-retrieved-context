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
| `ctxauth/rag/` | RAG-конвейер: разбиение, индекс, ретривер, промпт, LLM, инструменты, постобработка, журнал |
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

Детектирование без запуска LLM, 1100 примеров (PIArena NQ/MS MARCO/HotpotQA + SEP + BIPIA-email):

| Защита | Precision | Recall | F1 | FPR | ASR до→после | удалено чистого |
|---|---|---|---|---|---|---|
| без фильтра | — | — | — | 0.00 | 1.00→1.00 | 0.000 |
| по ключевым словам | 0.57 | 0.04 | 0.07 | 0.03 | 1.00→0.96 | 0.055 |
| **контроль полномочий (правила)** | **0.82** | **0.25** | **0.38** | **0.05** | **1.00→0.75** | **0.018** |

### Переносимость между бенчмарками (главный вывод)

Обучение на одних наборах, проверка на отложенном (воспроизводится
`scripts/experiment_generalization.py`, снимок — `docs/results_generalization.json`):

| Отложенный набор | Защита | Precision | Recall | FPR | удалено чистого |
|---|---|---|---|---|---|
| PIArena | контроль полномочий (правила) | 0.83 | 0.42 | **0.08** | **0.019** |
| PIArena | правила + ML (gated) | 0.73 | 0.48 | 0.18 | 0.026 |
| PIArena | обучаемый бинарный детектор | 0.51 | 0.98 | **0.96** | **0.97** |

Вывод: обучаемый детектор на незнакомом наборе **ломается** — блокирует почти весь контекст
(FPR 0.96, удаляет 97 % чистого текста). Правиловое ядро метода переносится устойчиво (FPR 0.08,
удаляет 2 % чистого), а обучаемая надстройка `gated` расширяет границу recall ценой роста FPR —
это настраиваемый компромисс (`gate`). На наборе SEP (скрытая подмена задачи) правила слабы
(recall 0.02) — это honest-ограничение, где выигрывает обучаемый детектор.
Это согласуется с известным наблюдением о плохой переносимости детекторов (напр. авторы PIArena).
Снимки метрик: `docs/results_indistribution.json`, `docs/results_generalization.json`.

Ложные срабатывания на встроенном «трудном» корпусе (манулы, статьи о безопасности, регламенты):
FPR 0.034.

Документация: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/BENCHMARKS.md](docs/BENCHMARKS.md).

## Статус

Сделано: RAG-конвейер, основной метод (правила + обучаемый скорер), встроенный корпус.

Остаточные ложные срабатывания на «трудных» безопасных документах — около 3 % фрагментов
(пограничные случаи: инструкции администратору, где действие и описание действия неразличимы).

Не сделано: веб-интерфейс, прогон атак через реальную LLM,
загрузчики дополнительных корпусов. Прогоны атак выполняются официальными
скриптами бенчмарков (BIPIA, AgentDojo, PIArena, SEP) с локальной моделью.

Связь «техника → вид влияния» в `taxonomy.py` рабочая — при необходимости уточняется.

## Командная строка

```bash
python -m ctxauth demo                                  # один запрос через конвейер
python -m ctxauth fpr                                   # ложные срабатывания на встроенном корпусе
python -m ctxauth eval --ext ./ext --limit 200 --out docs/results.json
python -m ctxauth eval --ext ./ext --holdout piarena    # кросс-бенчмарковая проверка обобщения
python -m ctxauth train-clf --ext ./ext --out model.pkl # обучить бинарный детектор-baseline
PYTHONPATH=. python scripts/experiment_generalization.py --ext ./ext --out docs/results_generalization.json
python -m pytest -q                                     # тесты
```
