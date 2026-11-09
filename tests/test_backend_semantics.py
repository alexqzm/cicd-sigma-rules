"""Как бэкенд pySigma для SQLite переводит корреляцию — проверка утверждений docs/correlation.md.

Запрос бэкенда исполняется на тех же эталонных событиях. Он ждёт таблицу logs со столбцом
timestamp в виде строки даты (julianday) и не проверяет порядок событий.
"""

import sqlite3
from datetime import datetime, timezone

from sigma.backends.sqlite import sqliteBackend

from tools.common import EVENTS, load_events, rule_files
from tools.harness import Harness


def _correlation_file():
    return next(rf for rf in rule_files() if rf.correlation)


def _fired(sql: str, events: list[dict]) -> set[str]:
    db = sqlite3.connect(":memory:")
    db.execute("CREATE TABLE logs (timestamp, action, event, repo)")
    for e in events:
        ts = datetime.fromtimestamp(e["@timestamp"] / 1000, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        db.execute("INSERT INTO logs VALUES (?, ?, ?, ?)", (ts, e["action"], e["event"], e["repo"]))
    return {row[0] for row in db.execute(sql)}


def test_sqlite_correlation_query_does_not_check_order():
    rf = _correlation_file()
    queries = sqliteBackend().convert(rf.collection)
    assert len(queries) == 1
    sql = queries[0]
    assert "GROUP BY repo" in sql and "rule_count >= 2" in sql
    match = load_events(EVENTS / rf.key / "match.jsonl")
    nomatch = load_events(EVENTS / rf.key / "nomatch.jsonl")
    assert _fired(sql, match) == {"example-org/web", "example-org/cli"}
    # сценарий C: workflow_dispatch раньше pull_request_target — по Sigma не срабатывает,
    # а запрос бэкенда срабатывает, потому что порядок событий не проверяет
    assert _fired(sql, nomatch) == {"example-org/sdk"}


def test_sqlite_correlation_span_covers_whole_group():
    """Окно сравнивается с разбросом всех событий группы, а не скользит по журналу."""
    rf = _correlation_file()
    sql = sqliteBackend().convert(rf.collection)[0]
    base = 1_793_610_000_000
    hour = 3_600_000
    events = [
        {"@timestamp": base, "action": "workflows.created_workflow_run", "event": "pull_request_target",
         "repo": "example-org/web"},
        # через сутки — пара, которая по Sigma срабатывает (10 минут между событиями)
        {"@timestamp": base + 24 * hour, "action": "workflows.created_workflow_run",
         "event": "pull_request_target", "repo": "example-org/web"},
        {"@timestamp": base + 24 * hour + 600_000, "action": "workflows.created_workflow_run",
         "event": "workflow_dispatch", "repo": "example-org/web"},
    ]
    assert _fired(sql, events) == set()
    # по спецификации Sigma (стенд tests/) пара через сутки срабатывает
    assert Harness(events).correlate(rf.correlation) == {("example-org/web",): [1, 2]}
