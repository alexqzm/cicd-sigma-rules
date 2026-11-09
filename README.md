# cicd-sigma-rules

[![CI](https://github.com/alexqzm/cicd-sigma-rules/actions/workflows/ci.yml/badge.svg)](https://github.com/alexqzm/cicd-sigma-rules/actions/workflows/ci.yml)

Правила [Sigma](https://sigmahq.io) для обнаружения атак на конвейеры сборки и цепочку поставки
ПО: журнал аудита GitHub (GitHub Actions, исполнители, защита веток и выпусков) и процессы на
сборочных хостах Linux. Каждое правило привязано к инцидентам, рискам OWASP CI/CD и процессам
ГОСТ Р 56939-2024, проверено на эталонных событиях, а запросы для OpenSearch и Elasticsearch
исполняются в самих движках в CI.

Репозиторий — часть работы над диссертацией «Метод обеспечения целостности цепочки сборки и
обновления программного обеспечения киберфизических систем на основе графа доказательств»:
наблюдаемые в SIEM события сборочного конвейера как свидетельства для графа доказательств.

## Правила

14 файлов правил: 10 правил журнала аудита GitHub, одна корреляция и 3 правила создания
процессов в Linux. Полная таблица с ATT&CK, инцидентами, OWASP и ГОСТ —
[`docs/rules.md`](docs/rules.md).

| Правило | Уровень | Что ловит |
|---|---|---|
| Workflow Execution Protection Violation | средний | запуск рабочего процесса нарушил политику, ограничивающую акторов и триггеры (в том числе `pull_request_target`) |
| pull_request_target Run in Public Repository | низкий | запуск по `pull_request_target` в публичном репозитории |
| pull_request_target Run Followed by workflow_dispatch Run | низкий | корреляция: запуск по `pull_request_target`, а за ним в течение часа ручной запуск в том же репозитории (схема Nx, 2025) |
| Self-Hosted Runner Registered to Public Repository | средний | собственный исполнитель зарегистрирован в публичном репозитории |
| Runner Group Opened to Public Repositories | средний | группа исполнителей открыта публичным репозиториям |
| GITHUB_TOKEN Permission Policy Changed | низкий | изменены права `GITHUB_TOKEN` по умолчанию или право Actions одобрять запросы на слияние |
| Fork Pull Request Workflow Policy Changed | низкий | изменены политики запуска рабочих процессов из форков |
| Allowed Actions Policy Changed | низкий | изменён список разрешённых действий и переиспользуемых рабочих процессов |
| Immutable Releases Disabled or Policy Changed | средний | отключены неизменяемые выпуски (теги снова можно переносить) |
| Branch Protection, Ruleset or Deployment Protection Rule Removed | средний | снята защита ветки, удалён набор правил или правило защиты развёртывания |
| Branch Protection Requirement Overridden | средний | администратор обошёл требование защиты ветки |
| Search for GitHub Actions Runner Secret Markers | высокий | поиск маркера `isSecret` в дампе памяти исполнителя или загрузка `memdump.py` (tj-actions/changed-files, 2025) |
| Node.js Process Launching AI Coding CLI With Permission Bypass Flag | высокий | скрипт Node.js или Bun запускает `claude`, `gemini` или `q` с отключёнными подтверждениями (Nx s1ngularity, 2025) |
| AI Coding CLI Launched With Permission Bypass Flag | низкий | то же при любом родительском процессе — для поиска угроз |

Правила дополняют, а не повторяют [SigmaHQ](https://github.com/SigmaHQ/sigma): там есть общие
правила для журнала аудита GitHub (например, любое изменение собственных исполнителей) и
индикаторы конкретных кампаний; здесь — условия конвейера, которые эксплуатировались в
инцидентах. Где правило уточняет правило SigmaHQ, это указано в поле `related`.

## Как проверены правила

1. **Валидаторы pySigma** (31 валидатор) с закреплённой версией MITRE ATT&CK 20.1: файл
   `attack-stix-data` проверяется по SHA-256, теги — по этой версии
   ([`tools/check.py`](tools/check.py)).
2. **Только задокументированные события и поля GitHub.** Каталог
   [`data/github-audit-events.json`](data/github-audit-events.json) собран из документации
   GitHub; тест проверяет, что правила и эталонные события не используют событий и полей, которых
   нет в документации для этого события.
3. **Эталонные события.** 85 синтетических событий (39 должны сработать, 46 — нет), включая
   соседние события, обратный порядок, границы окна и регистр. Условия правил исполняются
   SQL-запросами, которые строит бэкенд pySigma для SQLite, — проверяется и правило, и его
   конвертация; корреляции — по спецификации Sigma ([`tools/harness.py`](tools/harness.py)).
   Мутационная проверка: 12 ослаблений правил (убрать условие, расширить значение, сменить
   окно, поле группировки или порядок корреляции) — каждое ловится хотя бы одним событием
   `nomatch` ([`tests/test_mutations.py`](tests/test_mutations.py)).
4. **Запросы для SIEM** ([`conversions/`](conversions/)) генерируются официальными бэкендами
   pySigma; CI падает, если они разошлись с правилами.
5. **Исполнение в движках.** В CI запросы Lucene и EQL исполняются в OpenSearch 3.8.0 и
   Elasticsearch 9.5.5 (образы по дайджесту) на тех же эталонных событиях, при двух способах
   хранения строк — 80 исполнений на коммит ([`docs/siem.md`](docs/siem.md)).

Зависимости закреплены по версиям и хешам (`requirements.txt`, не новее 26.10.2026), действия
GitHub — по SHA коммита.

## Находки

- **Бэкенд EQL и логические поля.** Для `public_repo: true` pySigma-backend-elasticsearch 2.1.1
  пишет `public_repo:true`, а Elasticsearch 9.5.5 отклоняет `:` для логических полей (HTTP 400);
  с `==` запрос работает. Затронуты три правила.
- **Бэкенд EQL и корреляция `temporal_ordered`.** Запрос заканчивается на `by  with runs=2` с
  пустым полем и не разбирается; без этого хвоста — верен и находит ровно нужные сценарии.
- **Корреляции не переносятся между бэкендами.** SQLite не проверяет порядок и меряет окно по
  всей группе; для `temporal` ES|QL и Splunk режут время на фиксированные корзины, а EQL не
  ограничивает время вовсе. Проверено исполнением, кроме Splunk —
  [`docs/correlation.md`](docs/correlation.md).
- **Регистр.** Sigma сравнивает строки без учёта регистра, запрос Lucene в поле `keyword` без
  нормализатора — с учётом: событие `grep -aoi issecret` запрос Lucene находит только при
  нормализаторе `lowercase`, в обоих движках.
- **ATT&CK v20.** Тактики Defense Evasion в ATT&CK 20.1 нет (есть Stealth и Defense Impairment),
  T1562 Impair Defenses отозвана в пользу T1685; теги вроде `attack.defense-evasion` валидатор
  pySigma с ATT&CK 20.1 отклоняет.
- **Контекст GitHub.** Политики выполнения рабочих процессов ограничивают акторов и триггеры; для
  публичных репозиториев GitHub ввёл политику по умолчанию, блокирующую `pull_request_target`,
  с принудительным применением со 2 декабря 2026 г. Запуски по `pull_request_target` получают
  кэш ветки по умолчанию только для чтения, если рабочий процесс явно не объявил `cache-mode`
  с правом записи. После этой даты запуски по `pull_request_target` в публичных репозиториях
  означают явно разрешённое исключение.

## Быстрый старт

```sh
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements.txt
curl -sSfLo attack.json https://raw.githubusercontent.com/mitre-attack/attack-stix-data/a8db2f52eb933c9c99060c123e088b3326d3a607/enterprise-attack/enterprise-attack-20.1.json
python -m tools.check --attack attack.json   # валидаторы pySigma
python -m pytest -q                          # эталонные события, каталог, семантика
python -m tools.convert --check              # запросы совпадают с правилами
sigma convert -t splunk --without-pipeline rules/github/audit/   # свои запросы
```

## Структура

| Путь | Содержимое |
|---|---|
| `rules/` | правила Sigma (журнал аудита GitHub, корреляция, `process_creation` Linux) |
| `tests/events/` | эталонные события: `match.jsonl` и `nomatch.jsonl` для каждого правила |
| `conversions/` | запросы OpenSearch, Elasticsearch (Lucene и EQL) и Splunk |
| `mappings/mappings.yml` | инциденты, риски OWASP CI/CD, процессы ГОСТ Р 56939-2024 |
| `data/github-audit-events.json` | каталог событий и полей журнала аудита GitHub |
| `pipelines/` | конвейер полей для KUMA (предложение, в KUMA не проверен) |
| `tools/` | проверка, стенд, конвертация, таблица, проверка в движках |
| `docs/` | [правила](docs/rules.md), [источники и допущения](docs/logsources.md), [SIEM](docs/siem.md), [корреляции](docs/correlation.md), [KUMA](docs/kuma.md) |

## Связь с другими репозиториями

Инциденты — записи атласа [cps-supply-chain-atlas](https://github.com/alexqzm/cps-supply-chain-atlas)
(закреплённый коммит проверяется в CI). Процессы ГОСТ Р 56939-2024 — по модели
[rbpo-evidence](https://github.com/alexqzm/rbpo-evidence). Срабатывание правила или его
отсутствие на журнале конвейера — наблюдаемое свидетельство для процессов 5.12–5.15 и 5.20
(оценка автора); гейт допуска — [scii-gate](https://github.com/alexqzm/scii-gate).

## Ограничения

- Эталонные события синтетические: проверяется логика правил и конвертации, а не частота ложных
  срабатываний на реальных журналах. Все правила — `status: experimental`.
- Часть значений полей GitHub не задокументирована; допущения перечислены в
  [`docs/logsources.md`](docs/logsources.md).
- Запросы Splunk не исполнялись; в KUMA правила не проверялись.
- Сопоставления с инцидентами, OWASP и ГОСТ — оценка автора.

## Лицензии

Правила (`rules/`) — [Detection Rule License 1.1](LICENSE.Detection.Rules.md), как в SigmaHQ.
Код, документация и данные — [Apache-2.0](LICENSE). Имена событий и полей в
`data/github-audit-events.json` взяты из документации GitHub
([github/docs](https://github.com/github/docs), CC BY 4.0).

## Цитирование

См. [`CITATION.cff`](CITATION.cff).

## English summary

Sigma rules for attacks on CI/CD pipelines and the software supply chain: GitHub audit log
(Actions execution protections, `pull_request_target`, self-hosted runners, token and fork
policies, immutable releases, branch protection) and Linux process creation on build hosts
(runner memory secret scraping as in tj-actions/changed-files, AI coding CLIs launched with
permission bypass flags as in Nx s1ngularity). Each rule is mapped to incidents, OWASP Top 10
CI/CD risks and GOST R 56939-2024 processes and is tested on 85 synthetic reference events:
rule conditions run as SQL produced by the pySigma SQLite backend, correlations follow the
Sigma specification. Queries generated by the official pySigma backends are executed in
OpenSearch 3.8.0 and Elasticsearch 9.5.5 in CI. Findings: the EQL backend emits `field:true`
for booleans (rejected by Elasticsearch) and a malformed tail for `temporal_ordered`
correlations; correlation semantics differ across backends (no ordering in SQLite, fixed
buckets in ES|QL and Splunk, no time window in EQL `sample`); Lucene wildcard queries on
non-normalized keyword fields are case-sensitive unlike Sigma.
