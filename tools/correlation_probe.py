"""Как бэкенды Elasticsearch переводят корреляцию temporal — проверка в движке.

Правило репозитория — temporal_ordered. Здесь берётся его вариант с type: temporal (те же базовые
правила, group-by repo, окно 1h), переводится бэкендами ES|QL и EQL и исполняется в
Elasticsearch на трёх парах событий pull_request_target → workflow_dispatch в разных
репозиториях. По спецификации Sigma срабатывают пары near (10 минут) и cross (40 минут через
границу часа) и не срабатывает far (5 часов). Ожидаемые исходы — наблюдаемое поведение
бэкендов, описанное в docs/correlation.md; если оно изменится, проверка упадёт.

usage: python -m tools.correlation_probe --url http://localhost:9201
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone

from sigma.backends.elasticsearch import EqlBackend, ESQLBackend
from sigma.collection import SigmaCollection

from .common import RULES
from .siem_it import Engine, load_index

RULE = RULES / "github" / "correlation" / "github_pull_request_target_then_workflow_dispatch.yml"
INDEX = "csr-correlation-probe"


def _ms(hh: int, mm: int) -> int:
    return int(datetime(2026, 11, 2, hh, mm, tzinfo=timezone.utc).timestamp() * 1000)


PAIRS = {  # repo → (время pull_request_target, время workflow_dispatch)
    "example-org/near": (_ms(9, 5), _ms(9, 15)),
    "example-org/cross": (_ms(10, 40), _ms(11, 20)),
    "example-org/far": (_ms(12, 0), _ms(17, 0)),
}
SIGMA = {"example-org/near", "example-org/cross"}
#: наблюдаемое поведение бэкендов (pySigma-backend-elasticsearch 2.1.1)
EXPECTED = {
    "esql": {"example-org/near"},  # окна — фиксированные корзины date_trunc: cross не находится
    "eql": {"example-org/near", "example-org/cross", "example-org/far"},  # sample без окна
}


def temporal_variant() -> SigmaCollection:
    text = RULE.read_text(encoding="utf-8").replace("type: temporal_ordered", "type: temporal")
    return SigmaCollection.from_yaml(text)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True)
    args = parser.parse_args(argv)
    engine = Engine(args.url)
    docs = {}
    for repo, (t1, t2) in PAIRS.items():
        name = repo.split("/")[1]
        docs[f"{name}-prt"] = {"@timestamp": t1, "action": "workflows.created_workflow_run",
                               "event": "pull_request_target", "repo": repo}
        docs[f"{name}-dispatch"] = {"@timestamp": t2, "action": "workflows.created_workflow_run",
                                    "event": "workflow_dispatch", "repo": repo}
    load_index(engine, INDEX, "keyword", docs)
    queries = {
        "esql": ESQLBackend().convert(temporal_variant())[0],
        "eql": EqlBackend().convert(temporal_variant())[0],
    }
    found = {}
    status, body = engine.call("POST", "/_query", {"query": queries["esql"]})
    if status != 200:
        print(f"ES|QL: HTTP {status}: {body}")
        return 1
    cols = [c["name"] for c in body["columns"]]
    found["esql"] = {row[cols.index("repo")] for row in body["values"]}
    status, body = engine.call("POST", f"/{INDEX}/_eql/search", {"query": queries["eql"], "size": 100})
    if status != 200:
        print(f"EQL: HTTP {status}: {body}")
        return 1
    found["eql"] = {seq["join_keys"][0] for seq in body["hits"].get("sequences", [])}
    engine.call("DELETE", f"/{INDEX}")
    print(f"{engine.info()}; по Sigma срабатывают: {sorted(SIGMA)}")
    bad = 0
    for lang, query in queries.items():
        ok = found[lang] == EXPECTED[lang]
        bad += not ok
        print(f"{lang}: найдено {sorted(found[lang])}, ожидалось {sorted(EXPECTED[lang])} — "
              f"{'совпало' if ok else 'РАСХОДИТСЯ'}\n{query}\n")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
