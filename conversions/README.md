# Запросы для SIEM

Сгенерированы `python -m tools.convert` из правил `rules/` без конвейера обработки
(`--without-pipeline`): имена полей — как в правилах. Вручную не правятся; CI проверяет,
что запросы совпадают с правилами (`python -m tools.convert --check`).

| Цель | Бэкенд | Версия | Запросов |
|---|---|---|---|
| `opensearch/` — OpenSearch, Lucene (query_string) | pySigma-backend-opensearch | 2.0.3 | 13 из 14 |
| `elasticsearch/` — Elasticsearch, Lucene (query_string) | pySigma-backend-elasticsearch | 2.1.1 | 13 из 14 |
| `elasticsearch-eql/` — Elasticsearch, EQL | pySigma-backend-elasticsearch | 2.1.1 | 14 из 14 |
| `splunk/` — Splunk, SPL | pySigma-backend-splunk | 2.1.0 | 13 из 14 |

pySigma 1.5.1.

## Не поддерживается бэкендом

| Правило | Цель | Сообщение бэкенда |
|---|---|---|
| `github_pull_request_target_then_workflow_dispatch` | `opensearch` | Backend does not support correlation rules. |
| `github_pull_request_target_then_workflow_dispatch` | `elasticsearch` | Backend does not support correlation rules. |
| `github_pull_request_target_then_workflow_dispatch` | `splunk` | Correlation type 'temporal_ordered' is not supported by backend. |

## Проверка в движках

`python -m tools.siem_it` исполняет запросы `opensearch/`, `elasticsearch/` и
`elasticsearch-eql/` в OpenSearch и Elasticsearch на эталонных событиях (в CI — на каждый
коммит). Запросы `splunk/` в Splunk не исполнялись. Известные расхождения:

| Правило | Цель | Хранение строк | Причина | С правкой запрос проходит |
|---|---|---|---|---|
| `github_pull_request_target_run_public_repo` | `elasticsearch-eql` | keyword, lowercase | бэкенд EQL сравнивает логическое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `public_repo:true` → `public_repo == true` |
| `github_runner_group_allows_public_repos` | `elasticsearch-eql` | keyword, lowercase | бэкенд EQL сравнивает логическое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `runner_group_allow_public:true` → `runner_group_allow_public == true` |
| `github_self_hosted_runner_registered_public_repo` | `elasticsearch-eql` | keyword, lowercase | бэкенд EQL сравнивает логическое поле оператором «:», а Elasticsearch принимает «:» только для строк и предлагает «==» (HTTP 400) | `public_repo:true` → `public_repo == true` |
| `github_pull_request_target_then_workflow_dispatch` | `elasticsearch-eql` | keyword, lowercase | бэкенд EQL дописывает к последовательности «by  with runs=2» с пустым полем, и запрос не разбирается (HTTP 400) | удалить `by  with runs=2` |
| `proc_creation_lnx_runner_secret_marker_search` | `opensearch` | keyword | в поле keyword без нормализатора запрос Lucene с подстановкой чувствителен к регистру, а правило Sigma — нет: «grep -i issecret» не находится; с нормализатором lowercase находится | — |
| `proc_creation_lnx_runner_secret_marker_search` | `elasticsearch` | keyword | в поле keyword без нормализатора запрос Lucene с подстановкой чувствителен к регистру, а правило Sigma — нет: «grep -i issecret» не находится; с нормализатором lowercase находится | — |

Семантика корреляций различается по бэкендам — см. [`docs/correlation.md`](../docs/correlation.md).
