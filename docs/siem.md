# Запросы для SIEM и проверка в движках

## Что лежит в conversions/

Запросы сгенерированы официальными бэкендами pySigma без конвейера обработки: имена полей — как
в правилах (поля журнала аудита GitHub и поля `process_creation` таксономии Sigma). Версии
бэкендов и список неподдерживаемых пар «правило — цель» — в
[`conversions/README.md`](../conversions/README.md).

| Каталог | Язык | Куда подставлять |
|---|---|---|
| `opensearch/` | Lucene (`query_string`) | поиск и мониторы OpenSearch |
| `elasticsearch/` | Lucene (`query_string`) | поиск и правила Elasticsearch с запросом Lucene |
| `elasticsearch-eql/` | EQL | `_eql/search`, правила EQL |
| `splunk/` | SPL | поиск Splunk |

Если события в вашей SIEM нормализованы (например, в ECS) и поля называются иначе, запросы
нужно пересобрать со своим конвейером pySigma:

```sh
python -m pip install --require-hashes -r requirements.txt
sigma convert -t opensearch_lucene -p my-fields.yml rules/github/audit/
```

## Как проверены запросы

[`tools/siem_it.py`](../tools/siem_it.py) для каждого правила загружает его эталонные события
(`match.jsonl` и `nomatch.jsonl`) в отдельный индекс и исполняет запрос из `conversions/`:
Lucene — через `query_string`, EQL — через `_eql/search`. Запрос должен найти все события
`match` и ни одного `nomatch`; для корреляции — по последовательности в каждой группе `match`.

В CI (задание `siem`) это делается на каждый коммит в двух движках, образы закреплены по
дайджесту:

- OpenSearch 3.8.0 — `opensearchproject/opensearch@sha256:fafe3fc3587088674669235575aa166228c48bdb940294a8cdbbc1da75236a40`;
- Elasticsearch 9.5.5 — `docker.elastic.co/elasticsearch/elasticsearch@sha256:13b4a40bb095774f5fda635e45fd5677cc6a26565e42b24997b0c72b88e75984`.

Строковые поля индексируются как `keyword` в двух режимах: без нормализатора (поиск с учётом
регистра) и с нормализатором `lowercase`. `@timestamp` — дата в миллисекундах от эпохи. Итого
на коммит: 13 запросов Lucene в OpenSearch и 13 Lucene + 14 EQL в Elasticsearch, каждый в двух
режимах, — 80 исполнений. Отчёт — в сводке задания.

Запросы Splunk в Splunk не исполнялись.

## Что нашлось

Известные расхождения перечислены в [`tools/known_issues.py`](../tools/known_issues.py) и в
`conversions/README.md`. Проверка не падает на них, но падает, если такой случай неожиданно
прошёл (запись устарела), а для дефектов бэкенда — если не прошёл исправленный запрос.

1. **EQL и логические поля.** Для `public_repo: true` бэкенд EQL пишет `public_repo:true`.
   Elasticsearch 9.5.5 отвечает HTTP 400: оператор `:` принимает только строки, предлагается
   `==`. С `public_repo == true` запрос находит ровно события `match`. Затронуты три правила.
2. **EQL и temporal_ordered.** Запрос корреляции заканчивается на `by  with runs=2` с пустым
   полем — синтаксическая ошибка (HTTP 400). Без этого хвоста запрос верен: найдены ровно
   сценарии, которые срабатывают по Sigma (см. [`correlation.md`](correlation.md)).
3. **Регистр в Lucene.** Значения в Sigma сравниваются без учёта регистра, а запрос Lucene с
   подстановкой в поле `keyword` без нормализатора — с учётом: `grep -aoi issecret` не
   находится правилом поиска маркеров секретов. С нормализатором `lowercase` находится в обоих
   движках. Вывод для эксплуатации: поля, по которым ищут правила (`CommandLine`, `Image`,
   `ParentImage`), стоит хранить с нормализатором `lowercase` или искать по ним без учёта
   регистра другим способом.

Остальные запросы нашли ровно эталонные события: в каждом движке 12 из 13 запросов Lucene в
режиме `keyword` и все 13 в режиме `lowercase`, а также 10 из 14 запросов EQL в обоих режимах.

## Как повторить локально

```sh
docker run -d --name os -p 9200:9200 -e discovery.type=single-node \
  -e DISABLE_SECURITY_PLUGIN=true -e DISABLE_INSTALL_DEMO_CONFIG=true \
  -e cluster.routing.allocation.disk.threshold_enabled=false opensearchproject/opensearch:3.8.0
docker run -d --name es -p 9201:9200 -e discovery.type=single-node \
  -e xpack.security.enabled=false -e cluster.routing.allocation.disk.threshold_enabled=false \
  docker.elastic.co/elasticsearch/elasticsearch:9.5.5
python -m tools.siem_it --engine opensearch --url http://localhost:9200 --strings lowercase
python -m tools.siem_it --engine elasticsearch --url http://localhost:9201 --strings keyword
python -m tools.correlation_probe --url http://localhost:9201
```

Порог заполнения диска отключён, потому что на машинах с почти полным диском движок иначе
запрещает создавать индексы.
