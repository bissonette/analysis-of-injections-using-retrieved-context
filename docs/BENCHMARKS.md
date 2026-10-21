# Бенчмарки: ссылки, скачивание, прогон атак, передача результатов

## 1. Где взять данные

Клонируйте нужные репозитории рядом с проектом, в каталог `ext/` (он в `.gitignore`):

```bash
mkdir -p ext && cd ext
git clone --depth 1 https://github.com/microsoft/BIPIA.git
git clone --depth 1 https://github.com/sleeepeer/PIArena.git
git clone --depth 1 https://github.com/egozverev/Should-It-Be-Executed-Or-Processed.git   # SEP
git clone --depth 1 https://github.com/uiuc-kang-lab/InjecAgent.git
git clone --depth 1 https://github.com/ethz-spylab/agentdojo.git
git clone --depth 1 https://github.com/LukeChen-go/indirect-pia-detection.git             # Chen et al., ACL 2025
git clone --depth 1 https://github.com/MYVAE/Instruction-detection.git                    # InstructDetector (Wen et al.)
git clone --depth 1 https://github.com/liu00222/Open-Prompt-Injection.git
git clone --depth 1 https://github.com/sleeepeer/PoisonedRAG.git
git clone --depth 1 https://github.com/microsoft/TaskTracker.git                          # ~800 МБ, part с HF
git clone --depth 1 https://github.com/agiresearch/ASB.git
git clone --depth 1 https://github.com/facebookresearch/wasp.git
```

| Бенчмарк | Что даёт | Напрямую используется загрузчиком |
|---|---|---|
| **BIPIA** (Yi et al.) — `microsoft/BIPIA` | indirect PI: контексты email/table/code + наборы атак, вставка в начало/середину/конец, режим base64 | `load_bipia` (email/table/code локально; QA/abstract — догрузка с HF) |
| **PIArena** (Geng et al., ACL 2026) — `sleeepeer/PIArena` | RAG-наборы (NQ, MS MARCO, HotpotQA), длинные контексты, 4 категории инъекций + искажение знаний; платформа атак/защит | `load_piarena` |
| **SEP** (Zverev et al.) — `egozverev/Should-It-Be-Executed-Or-Processed` | 9160 примеров instruction-vs-data, слово-свидетель исполнения | `load_sep` |
| **Chen et al.** (ACL 2025) — `LukeChen-go/indirect-pia-detection` | Inj-SQuAD, Inj-TriviaQA + обучающие наборы (позиция head/middle/tail) | можно добавить в loaders |
| **InjecAgent** — `uiuc-kang-lab/InjecAgent` | 1054 агентных тест-кейса (direct harm / data stealing) | трассы/кейсы |
| **AgentDojo** — `ethz-spylab/agentdojo` | агентные сценарии + **записанные прогоны ~29 конфигураций моделей** с флагом успеха атаки | анализ трасс (см. §4) |
| **InstructDetector** (Wen et al.) — `MYVAE/Instruction-detection` | метод-детектор (код), верхний baseline | сравнение |
| **TaskTracker** (Abdelnabi et al.) — `microsoft/TaskTracker` | 31k отравленных примеров + ответы Llama-3/Mistral/Mixtral с разметкой verifier | анализ ответов (см. §4) |
| **PoisonedRAG**, **ASB**, **WASP**, **Open-Prompt-Injection** | отравление корпуса, агентные атаки, веб-агенты | дополнительно |

Наборы MS MARCO, BEIR, FEVER, HotpotQA, NQ, FiQA, SciFact, NFCorpus (чистые) берутся через
PIArena/BIPIA или напрямую с HuggingFace `datasets`, когда он доступен.

## 2. Как соотнести атаки с полномочиями (схема разметки ТК↔П)

Это делает `ctxauth/data/loaders.py`: категория бенчмарка → навязываемый вид влияния.
Например PIArena: `phishing_injection`/`content_promotion` → **format** (форма/внешний канал),
`access_denial`/`infrastructure_failure` → **instructions** (подмена правил), `knowledge_corruption` → **content**
(вне области метода). SEP (внедрённая подзадача) → **task**. BIPIA: Marketing/Scams → format,
Task Automation / code-атаки → actions, остальное → task. Таблицы соответствия — в начале `loaders.py`,
их правят под итоговую таксономию модели угроз.

## 3. Прогон атак и выводы

### 3.1 Детектирование/защита без запуска LLM (быстро, детерминированно)
```bash
python -m ctxauth eval --ext ./ext --limit 200 --out docs/results.json
```
Сравнивает `no_filter`, `keyword`, метод `ctxauth` (и, с `--clf model.pkl`, обученный детектор)
по P/R/F1/FPR, ASR до/после, доле удалённого контекста, задержке.

Кросс-бенчмарковая проверка обобщения (обучить на одних наборах, проверить на отложенном):
```bash
python -m ctxauth eval --ext ./ext --limit 200 --holdout piarena
```

**Как делать выводы.** Смотрите на три вещи вместе: (1) снижение ASR (успех атаки) —
насколько метод режет доставку инъекций; (2) FPR и долю удалённого чистого контекста —
цену за это на безопасных данных; (3) разрыв in-distribution vs holdout — переносимость.
Ключевой наблюдаемый эффект: обучаемый бинарный детектор силён на знакомых наборах, но вне
распределения либо пропускает атаки, либо блокирует почти весь контекст; контроль полномочий
деградирует плавно и почти не трогает чистый контекст (см. `docs/results_indistribution.json`).

### 3.2 Прогон через реальную LLM (на вашей машине)
Поднимите локальную модель (HuggingFace/Ollama недоступны в облачной сессии, но доступны локально):
```bash
ollama pull qwen2.5:7b-instruct      # или vLLM / llama.cpp server
```
Запускайте **официальными скриптами самих бенчмарков** — они уже реализуют вставку атак,
вызов модели и подсчёт успеха: PIArena `python main.py …`, BIPIA `run.py`, AgentDojo CLI,
SEP `model_eval/`. В SEP успех атаки проверяется автоматически по слову-свидетелю.
Для прогона через наш конвейер с реальной моделью используйте
`OpenAICompatibleLLM(model=…, base_url="http://localhost:11434/v1")` в `Orchestrator`.

## 4. Анализ уже записанных прогонов (без запуска моделей)

Готовые результаты атак на реальных моделях лежат в самих репозиториях:
- **AgentDojo** `runs/<модель>/<сценарий>/…json` — поле `security` (True = атака НЕ прошла).
  Доля `security=False` = ASR модели; есть конфигурации с защитами (spotlighting, tool_filter,
  детектор) — готовые baseline'ы.
- **TaskTracker** `dataset_sampled/<модель>/…verifier.json` — метки `EXECUTED / REJECTED / NOT DETECTED`.
  Доля `EXECUTED` = ASR. Напр. Llama-3-8B: 7054 executed / 7502 rejected / 16578 not-detected.

## 5. Как прислать мне результаты для обучения классификатора

Пришлите один из вариантов (чем структурированнее, тем лучше):

1. **JSON-отчёт** `docs/results*.json` из `python -m ctxauth eval --out …` — для сравнения метрик.
2. **Размеченные примеры** в формате `AttackSample` (JSONL, по строке на фрагмент):
   ```json
   {"query": "...", "chunk_text": "...", "is_injected": true,
    "permission": "P6", "technique": "TK6", "source": "piarena/nq_rag", "intent": "qa"}
   ```
   На них я (а) обучу бинарный детектор и мульти-лейбл скорер видов влияния
   (`ctxauth/eval/train.py`), (б) настрою пороги, (в) пересчитаю метрики с честным
   разбиением train/test по источникам. Для обучения мульти-лейбл скорера нужны поле
   `permission` и, желательно, `injected_task`/`attack` в `meta` (несущий текст инъекции).
3. **Папку с прогонами реальной модели** (ответы + метки успеха) — посчитаю ASR в разрезах
   по модели/технике/виду влияния и сопоставлю с решениями метода.

Коммитьте данные **не в репозиторий** (они большие и часто под своей лицензией), а присылайте
ссылкой или архивом; я кладу их в `ext/` и запускаю загрузчики.
