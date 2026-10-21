# ctxauth — контроль полномочий retrieved-контекста в RAG-системах

Код ВКР (Поповская В., N3450): вместо бинарного детектирования prompt injection модуль К8
определяет, **какую часть поведения модели имеет право менять каждый retrieved-фрагмент**
(полномочия П1–П6), и пропускает / очищает / блокирует фрагмент до передачи в LLM.

## Структура

| Путь | Компонент модели угроз |
|---|---|
| `ctxauth/types.py`, `ctxauth/taxonomy.py` | П1–П6, ТК1–ТК10, соответствие К1–К14 модулям |
| `ctxauth/rag/` | стенд: чанкинг (К5), индекс (К6), ретривер (К7), промпт (К3), LLM (К9), регистратор инструментов (К10), постобработка (К11), журнал (К12) |
| `ctxauth/authority/` | **К8**: `intent.py` (запрос → делегированный профиль), `rules.py` + `analyzer.py` (заявляемое влияние предложения на П2–П6), `ml.py` (обучаемый скорер), `controller.py` (PASS / SANITIZE / BLOCK) |
| `ctxauth/data/builtin_corpus.py` | 35 безопасных документов, из них 19 «трудных» (УБИ-С10) для оценки ложных срабатываний |

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

Параметры К8 (`ControllerConfig`): `request_dependent=False` — статический профиль (абляция УБИ-С14),
`sanitize=False` — блокировать фрагмент целиком, `thresholds` — пороги по полномочиям;
`AuthorityAnalyzer(mode="rules"|"ml"|"max")`.

## Статус

Сделано: стенд К2–К12, модуль К8 на правилах, встроенный корпус.

Известная проблема: на «трудных» безопасных документах К8 на правилах ложно срабатывает
на ~12 % фрагментов (запреты «never/do not…», шаги регламентов, пересказ атак в статьях).

Не сделано: оркестратор К2 одним классом, веб-интерфейс К1, CLI, тесты, обученный ML-скорер,
baseline'ы и расчёт метрик, загрузчики внешних корпусов. Прогоны атак выполняются официальными
скриптами бенчмарков (BIPIA, AgentDojo, PIArena, SEP) с локальной моделью.

Связь УБИ-С ↔ П в `taxonomy.py` рабочая — сверить с текстом модели угроз.
