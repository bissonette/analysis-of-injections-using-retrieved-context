# Цитаты из статей по используемым бенчмаркам

Прямые цитаты из официальных источников (статьи / репозитории авторов) с переводом на русский.
Для каждого бенчмарка приведены: цитата об его назначении и цитата/данные о **статистике моделей
после тестов** (насколько модели оказались уязвимы). Цитаты о назначении взяты дословно из README
авторов; числовые результаты — по тексту статей и их обзорам, поэтому их следует сверить с
итоговыми таблицами статьи (ссылки по arXiv-идентификатору). arXiv из рабочего окружения был
недоступен, поэтому дословная сверка по PDF не проводилась.

---

## BIPIA — косвенные инъекции (базовый бенчмарк)
Yi et al. «Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models».
arXiv:2312.14197 · https://github.com/microsoft/BIPIA

> «These applications … are vulnerable to indirect prompt injection attacks, where malicious
> instructions embedded within external content compromise LLM's output, causing their responses to
> deviate from user expectations. … We introduce the first benchmark of indirect prompt injection
> attack, BIPIA, to measure the robustness of various LLMs and defenses against indirect prompt
> injection attacks.»

> «Эти приложения … уязвимы к косвенным инъекциям указаний, когда вредоносные инструкции,
> встроенные во внешний контент, компрометируют вывод модели, заставляя её ответы отклоняться от
> ожиданий пользователя. … Мы представляем первый бенчмарк косвенных инъекций указаний, BIPIA, для
> измерения устойчивости различных LLM и защит к косвенным инъекциям.»

**Статистика после тестов:** авторы показывают, что все протестированные LLM уязвимы к косвенным
инъекциям; успешность атак высока (во вторичных обзорах для Vicuna-7B приводится ASR ≈ 0.82), а
предложенные защиты снижают её ценой потери качества на чистых данных. (Сверить по таблицам статьи.)

---

## SEP — разделение «данные против указаний»
Zverev et al. «Can LLMs Separate Instructions From Data? And What Do We Even Mean By That?» (ICLR 2025).
arXiv:2403.06833 · https://github.com/egozverev/Should-It-Be-Executed-Or-Processed

> «We studied, formalized, and measured an important aspect of large language models (LLMs): their
> (in)ability to separate instruction from data in the inputs. … SEP Dataset … A collection of 9,160
> examples designed to test the models' ability to distinguish between instructions and data. The
> dataset covers 300 different subtasks across three domains.»

> «Мы изучили, формализовали и измерили важное свойство больших языковых моделей: их
> (не)способность отделять инструкции от данных во входных данных. … Набор SEP … содержит 9160
> примеров, предназначенных для проверки способности моделей различать инструкции и данные. Набор
> охватывает 300 различных подзадач в трёх областях.»

**Статистика после тестов:** «all models fail to achieve high separation» — ни одна модель не
достигает высокого разделения «данные/указания»; при этом полезность остаётся высокой (≈80 %), а
обычные меры (prompt engineering, дообучение) существенно проблему не решают. (Интересно, что
GPT-3.5 показывает разделение лучше GPT-4.)

---

## InjecAgent — атаки на инструменты агента (вид влияния «действия»)
Zhan et al. «InjecAgent: Benchmarking Indirect Prompt Injections in Tool-Integrated Large Language
Model Agents» (ACL 2024 Findings). arXiv:2403.02691 · https://github.com/uiuc-kang-lab/InjecAgent

> «External content introduces the risk of indirect prompt injection (IPI) attacks, where malicious
> instructions are embedded within the content processed by LLMs, aiming to manipulate these agents
> into executing detrimental actions against users. InjecAgent is a benchmark designed to evaluate
> the vulnerability of tool-integrated LLM agents to IPI attacks. It consists of 1,054 test cases
> that span 17 different user tools and 62 attacker tools.»

> «Внешний контент создаёт риск косвенных инъекций указаний (IPI): вредоносные инструкции
> встраиваются в контент, обрабатываемый моделью, чтобы заставить агента выполнить вредоносные для
> пользователя действия. InjecAgent — бенчмарк для оценки уязвимости агентов с инструментами к
> IPI-атакам. Он состоит из 1054 тест-кейсов, охватывающих 17 пользовательских и 62 атакующих
> инструмента.»

**Статистика после тестов (из статьи):** агент на GPT-4 с ReAct-промптом уязвим примерно в **24 %**
случаев в базовом режиме, и доля почти удваивается до **~47 %** при усиленной формулировке атаки;
дообученные агенты устойчивее (единицы процентов). Вывод: «ReAct-prompted GPT-4 vulnerable to
attacks 24% of the time».

---

## AgentDojo — агентные сценарии и записанные прогоны (анализ успешности)
Debenedetti et al. «AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and
Defenses for LLM Agents» (NeurIPS 2024). arXiv:2406.13352 · https://github.com/ethz-spylab/agentdojo

> «AgentDojo: A Dynamic Environment to Evaluate Prompt Injection Attacks and Defenses for LLM Agents.»
> (из названия) Среда моделирует реалистичное исполнение агента, где агент сам решает, какие
> инструменты вызвать, что отличает её от статичных наборов.

> «AgentDojo — динамическая среда для оценки атак инъекций указаний и защит от них для
> LLM-агентов.» Среда воспроизводит реалистичную работу агента: агент сам выбирает, какие
> инструменты вызвать.

**Статистика после тестов:** в работе у GPT-4o самая высокая целевая успешность атак — **≈53 %**
(targeted ASR 53.1 % для атаки «важное сообщение»); в таблице лидерборда gpt-4o-2024-05-13 —
**47.7 %**, тогда как claude-3-7-sonnet — **7.3 %**. Это совпадает с нашими замерами по записанным
прогонам (important_instructions ≈ 0.48). Отмечается «обратное масштабирование»: более способные
модели угнать проще.

---

## TaskTracker — обнаружение «увода задачи» (анализ успешности)
Abdelnabi et al. «Get my drift? Catching LLM Task Drift with Activation Deltas» (SaTML 2025).
arXiv:2406.00799 · https://github.com/microsoft/TaskTracker

> «Detects when an LLM deviates from a user's original instructions due to malicious prompts injected
> into external data sources. … Achieves over 0.99 ROC AUC on out-of-distribution test data spanning
> jailbreaks, malicious instructions, and unseen task domains.»

> «Обнаруживает, когда модель отклоняется от исходных инструкций пользователя из-за вредоносных
> указаний, внедрённых во внешние источники данных. … Достигает ROC AUC выше 0,99 на тестовых
> данных вне обучающего распределения, включающих джейлбрейки, вредоносные инструкции и незнакомые
> предметные области.»

**Статистика после тестов:** цифра 0,99 ROC AUC относится к их **детектору** увода задачи (а не к
успешности атак). По самим прогонам моделей в наборе (наш подсчёт): инъекция выполнена в 23–47 %
случаев, но ещё в 42–53 % **не замечена** моделью.

---

## Raccoon — извлечение системного промпта (вид влияния «раскрытие»)
Wang et al. «Raccoon: Prompt Extraction Benchmark of LLM-Integrated Applications» (ACL 2024 Findings).
arXiv:2406.06737 · https://github.com/M0gician/RaccoonBench

> «Raccoon is a test bench for prompt extraction attacks on LLM-Integrated Applications. … The
> benchmark encompasses 14 categories of prompt extraction attacks, with additional compounded
> attacks that closely mimic the strategies of potential attackers.»

> «Raccoon — испытательный стенд для атак извлечения промпта на приложениях с LLM. … Бенчмарк
> охватывает 14 категорий атак извлечения промпта, а также составные атаки, близко имитирующие
> стратегии реальных злоумышленников.»

**Статистика после тестов:** «all seven evaluated models are vulnerable in an undefended state» —
все семь протестированных моделей уязвимы без защиты; под защитой отдельные конфигурации (например,
GPT-4-1106 с длинным шаблоном) устойчивы. Отмечается связь: чем способнее модель, тем она уязвимее.

---

## PIArena — платформа оценки инъекций в RAG
Geng et al. «PIArena: A Platform for Prompt Injection Evaluation» (ACL 2026).
arXiv:2604.08499 · https://github.com/sleeepeer/PIArena

> «PIArena is an easy-to-use toolbox and also a comprehensive benchmark for researching prompt
> injection attacks and defenses.»

> «PIArena — удобный инструментарий и одновременно комплексный бенчмарк для исследования атак
> инъекций указаний и защит от них.»

**Статистика после тестов:** авторы сообщают об ограниченной переносимости защит между задачами и
об их уязвимости к адаптивным атакам, а также о фундаментальной сложности, когда внедрённая задача
совпадает с целевой. Это прямо мотивирует проверку нашего метода на переносимость.

---

> Примечание: названия статей и формулировки приведены по официальным репозиториям и страницам
> arXiv авторов. Номера arXiv следует указывать как идентификатор, так как названия и версии
> статей со временем менялись.
