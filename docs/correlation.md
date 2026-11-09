# Корреляция: одно правило Sigma — разные запросы

Правило [`github_pull_request_target_then_workflow_dispatch`](../rules/github/correlation/github_pull_request_target_then_workflow_dispatch.yml)
— корреляция `temporal_ordered`: запуск по `pull_request_target`, а за ним не позже чем через час
ручной запуск (`workflow_dispatch`) в том же репозитории (`group-by: repo`). По спецификации
Sigma срабатывание требует обоих событий, в этом порядке и в пределах окна.

Правило проверено трижды: эталонной реализацией семантики Sigma в стенде `tests/`, SQL-запросом
бэкенда SQLite и запросом EQL в Elasticsearch. Ниже — что получилось. Всё, кроме раздела
«Splunk», проверено исполнением; версии: pySigma 1.5.1, pySigma-backend-sqlite 1.2.4,
pySigma-backend-elasticsearch 2.1.1, pySigma-backend-opensearch 2.0.3,
pysigma-backend-splunk 2.1.0, Elasticsearch 9.5.5.

## Эталонные сценарии

| Сценарий | События | По Sigma |
|---|---|---|
| A | `pull_request_target`, через 20 минут `workflow_dispatch` | срабатывает |
| B | `pull_request_target`, между ними `push`, `workflow_dispatch` через 59 минут | срабатывает |
| C | `workflow_dispatch`, через 10 минут `pull_request_target` | нет — обратный порядок |
| D | `pull_request_target`, через 61 минуту `workflow_dispatch` | нет — вне окна |
| E | `pull_request_target` и `workflow_dispatch` в разных репозиториях | нет — разные группы |
| F | `pull_request_target`, через 5 минут `push` | нет — второго шага нет |

Сценарии A и B лежат в `tests/events/<правило>/match.jsonl`, C–F — в `nomatch.jsonl`, каждый в
своём репозитории, чтобы не влиять друг на друга.

## Эталонная реализация

[`tools/harness.py`](../tools/harness.py): базовые правила исполняются SQL-запросами бэкенда
SQLite, а корреляция вычисляется по спецификации — для каждого события первого шага ищется
цепочка следующих шагов по порядку журнала, не дальше окна от первого события. Корректность
проверяют `tests/test_harness.py` (восемь случаев для `temporal` и `temporal_ordered`, включая
границу окна) и сами сценарии A–F.

## Что делают бэкенды

| Бэкенд | Запрос | Расхождение с Sigma | Чем подтверждено |
|---|---|---|---|
| SQLite | `GROUP BY repo HAVING rule_count >= 2` и разброс времени всех событий группы не больше окна | порядок не проверяется: срабатывает на C; окно меряется по всей группе: пара в 10 минут не находится, если в той же группе сутками раньше был ещё один `pull_request_target` | `tests/test_backend_semantics.py` |
| Elasticsearch, EQL | `sequence by repo with maxspan=1h [...] [...]` и хвост `by  with runs=2` | хвост с пустым полем — синтаксическая ошибка, Elasticsearch отвечает HTTP 400 | CI, задание `siem` |
| Elasticsearch, EQL без хвоста | то же без ` by  with runs=2` | нет: найдены ровно A и B, ни одного события из C–F | CI, задание `siem` (правка запроса из `tools/known_issues.py`) |
| OpenSearch и Elasticsearch, Lucene | — | корреляции не поддерживаются бэкендом | `conversions/README.md` |
| Splunk | — | тип `temporal_ordered` бэкенд не поддерживает | `conversions/README.md` |

Запрос EQL без хвоста совпал со стендом на всех шести сценариях: это независимое подтверждение
эталонной реализации движком, у которого последовательности — встроенная операция.

## Тот же шаблон с type: temporal

Без требования порядка (`type: temporal`) бэкенды переводят окно по-разному.
[`tools/correlation_probe.py`](../tools/correlation_probe.py) исполняет запросы в Elasticsearch
на трёх парах `pull_request_target` → `workflow_dispatch`: через 10 минут (near), через 40 минут
через границу часа (cross) и через 5 часов (far). По Sigma срабатывают near и cross.

| Бэкенд | Как задано окно | Найдено | Расхождение |
|---|---|---|---|
| ES\|QL | фиксированные корзины `date_trunc(1hours, @timestamp)` | near | cross не находится: события в соседних корзинах |
| EQL | `sample by repo` без ограничения по времени | near, cross, far | far находится: окна нет |
| Splunk (не исполнялось) | фиксированные корзины `bin _time span=1h` | — | по виду запроса — как ES\|QL |
| SQLite | разброс всех событий группы | — | как для `temporal_ordered`, без порядка |

## Вывод

Ни один бэкенд не дал без правки запроса с семантикой Sigma: SQLite не проверяет порядок и
меряет окно по всей группе; EQL для `temporal_ordered` выдаёт неразбираемый запрос (с правкой —
верный), а для `temporal` не ограничивает время; ES|QL и Splunk заменяют скользящее окно
фиксированными корзинами; Lucene-бэкенды корреляции не поддерживают. Правило Sigma переносимо
как спецификация, но не как готовый запрос: корреляции нужно проверять в целевом движке на
эталонных событиях с граничными случаями (порядок, граница окна, граница корзины, разные
группы). Для диссертации это довод за то, чтобы свидетельство «правило обнаружения проверено»
включало движок, версию бэкенда и набор эталонных событий, а не только текст правила (оценка
автора).
