# Прогон на живой локальной модели: пошаговая инструкция

Цель: получить успешность атак на **настоящей** модели (а не на «наихудшем» симуляторе),
с фильтром и без. Нужен компьютер с ~8 ГБ свободной памяти; GPU желателен, но не обязателен.

## Шаг 1. Установить Ollama и скачать модель (один раз)

- Windows/Mac: установить с https://ollama.com/download и запустить приложение.
- Linux: `curl -fsSL https://ollama.com/install.sh | sh`

Затем в терминале:
```bash
ollama pull qwen2.5:7b-instruct
```
(если памяти мало — `ollama pull qwen2.5:3b-instruct`; модель слабее, но прогон быстрее)

Проверка, что сервер жив:
```bash
curl http://localhost:11434/v1/models
```

## Шаг 2. Подготовить проект (один раз)

```bash
git clone https://github.com/bissonette/analysis-of-injections-using-retrieved-context.git
cd analysis-of-injections-using-retrieved-context
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt

mkdir -p ext && cd ext
git clone --depth 1 https://github.com/microsoft/BIPIA.git
git clone --depth 1 https://github.com/sleeepeer/PIArena.git
git clone --depth 1 https://github.com/egozverev/Should-It-Be-Executed-Or-Processed.git
git clone --depth 1 https://github.com/uiuc-kang-lab/InjecAgent.git
git clone --depth 1 https://github.com/M0gician/RaccoonBench.git
git clone --depth 1 https://github.com/LukeChen-go/indirect-pia-detection.git
cd ..
```

## Шаг 3. Прогон (одна команда)

Сначала маленький пробный (минут 10–20, ~60 атак):
```bash
PYTHONPATH=. .venv/bin/python scripts/experiment_endtoend.py --ext ./ext --limit 20 \
    --backend ollama --model qwen2.5:7b-instruct --out docs/endtoend_real_small.json
```
Если всё хорошо — полный (может занять несколько часов, можно оставить на ночь):
```bash
PYTHONPATH=. .venv/bin/python scripts/experiment_endtoend.py --ext ./ext --limit 150 \
    --backend ollama --model qwen2.5:7b-instruct --out docs/endtoend_real.json
```

Каждая атака прогоняется дважды (с фильтром и без), поэтому долго — это нормально.

## Шаг 4. Что прислать мне

1. Файл(ы) `docs/endtoend_real*.json` — главное.
2. Вывод команды из терминала (скопировать текст или скриншот) — там сводка.
3. Название модели и примерное время прогона.

## Что я сделаю с этим

- посчитаю реальную успешность атак до/после фильтра по видам влияния и сравню с «наихудшей»
  оценкой симулятора (реальные цифры будут ниже — модель исполняет не всё доставленное);
- найду атаки, которые реальная модель исполнила, а фильтр пропустил, — и дочиню правила по ним;
- проверю, не портит ли фильтр качество ответов на реальной модели;
- обновлю таблицы в документации и отчёт для преподавателя.

## Если что-то не работает

- `Connection refused` → Ollama не запущена: открой приложение или `ollama serve`.
- Очень медленно → возьми `qwen2.5:3b-instruct` и/или `--limit 20`.
- Нет какого-то бенчмарка → можно клонировать только часть из шага 2: скрипт пропустит отсутствующие.
