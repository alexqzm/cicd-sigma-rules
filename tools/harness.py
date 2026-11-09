"""Проверка правил на эталонных событиях.

Условия правил исполняются как запросы SQL, которые строит бэкенд pySigma для SQLite, — так
проверяется сама конвертация, а не отдельная реализация семантики Sigma. Корреляции temporal и
temporal_ordered вычисляются здесь по спецификации Sigma: события базовых правил с одинаковыми
значениями полей group-by, в пределах timespan, для temporal_ordered — в заданном порядке.
SQL-запрос корреляции из бэкенда SQLite для этого не годится: он не проверяет порядок событий и
сравнивает timespan с разбросом всех событий группы (см. docs/correlation.md).
"""

from __future__ import annotations

import json
import re
import sqlite3

from sigma.backends.sqlite import sqliteBackend
from sigma.correlations import SigmaCorrelationRule, SigmaCorrelationType
from sigma.rule import SigmaRule

from .common import strip_test

TABLE = "logs"
TIMESTAMP = "@timestamp"


def _sql_value(value):
    if isinstance(value, bool):
        return int(value)
    if value is None or isinstance(value, (int, float, str)):
        return value
    return json.dumps(value, ensure_ascii=False, sort_keys=True)


def rule_sql(rule: SigmaRule) -> str:
    """Запрос SQLite для одного правила, в том числе базового правила корреляции.

    Базовое правило корреляции бэкенд переводит в условие для вложения в запрос корреляции,
    а без generate и вовсе пропускает; поэтому оно переводится как отдельное правило — копия
    из его же словаря, без обратных ссылок на корреляцию.
    """
    if rule._backreferences or not rule._output:
        rule = SigmaRule.from_dict(rule.to_dict())
    queries = sqliteBackend().convert_rule(rule)
    if len(queries) != 1:
        raise ValueError(f"{rule.title}: ожидался один запрос, получено {len(queries)}")
    return queries[0].replace("<TABLE_NAME>", TABLE)


class Harness:
    """События в таблице SQLite в памяти; номер события — его индекс во входном списке."""

    def __init__(self, events: list[dict]):
        self.events = [strip_test(e) for e in events]
        self.db = sqlite3.connect(":memory:")
        columns: list[str] = []
        for event in self.events:
            for key in event:
                if key not in columns:
                    columns.append(key)
        defs = ", ".join(['"_eid" INTEGER PRIMARY KEY'] + [f'"{c}"' for c in columns])
        self.db.execute(f"CREATE TABLE {TABLE} ({defs})")
        for eid, event in enumerate(self.events):
            cols = ['"_eid"'] + [f'"{k}"' for k in event]
            marks = ", ".join("?" * len(cols))
            self.db.execute(
                f"INSERT INTO {TABLE} ({', '.join(cols)}) VALUES ({marks})",
                [eid] + [_sql_value(v) for v in event.values()],
            )

    def _run(self, sql: str) -> list[int]:
        while True:
            try:
                cursor = self.db.execute(sql)
                break
            except sqlite3.OperationalError as exc:
                missing = re.fullmatch(r"no such column: (.+)", str(exc))
                if not missing:
                    raise
                # поле правила, которого нет ни в одном событии, — пустой столбец
                self.db.execute(f'ALTER TABLE {TABLE} ADD COLUMN "{missing.group(1)}"')
        names = [d[0] for d in cursor.description]
        index = names.index("_eid")
        return sorted(row[index] for row in cursor.fetchall())

    def match(self, rule: SigmaRule) -> list[int]:
        return self._run(rule_sql(rule))

    def correlate(self, corr: SigmaCorrelationRule) -> dict[tuple, list[int]]:
        """Срабатывания корреляции: ключ группы → номера событий первой найденной цепочки."""
        if corr.type not in (SigmaCorrelationType.TEMPORAL, SigmaCorrelationType.TEMPORAL_ORDERED):
            raise NotImplementedError(f"тип корреляции {corr.type.name} не поддерживается")
        group_by = list(corr.group_by or [])
        span_ms = corr.timespan.seconds * 1000
        refs = [ref.rule for ref in corr.rules]
        hits: dict[tuple, list[tuple[int, int, int]]] = {}
        for step, rule in enumerate(refs):
            for eid in self.match(rule):
                event = self.events[eid]
                key = tuple(event.get(f) for f in group_by)
                hits.setdefault(key, []).append((int(event[TIMESTAMP]), eid, step))
        fired = {}
        for key, items in hits.items():
            items.sort()
            chain = (
                _ordered_chain(items, len(refs), span_ms)
                if corr.type == SigmaCorrelationType.TEMPORAL_ORDERED
                else _unordered_chain(items, len(refs), span_ms)
            )
            if chain:
                fired[key] = chain
        return fired


def _ordered_chain(items, steps, span_ms):
    """События шагов 0..steps-1 строго по порядку журнала, не дальше span_ms от первого."""
    for i, (t0, eid0, step0) in enumerate(items):
        if step0 != 0:
            continue
        chain, want = [eid0], 1
        for t, eid, step in items[i + 1:]:
            if t - t0 > span_ms:
                break
            if step == want:
                chain.append(eid)
                want += 1
                if want == steps:
                    return chain
    return None


def _unordered_chain(items, steps, span_ms):
    """По одному событию каждого шага в окне span_ms, начиная с любого события."""
    for i, (t0, _eid0, _step0) in enumerate(items):
        seen = {}
        for t, eid, step in items[i:]:
            if t - t0 > span_ms:
                break
            seen.setdefault(step, eid)
            if len(seen) == steps:
                return [seen[s] for s in range(steps)]
    return None
