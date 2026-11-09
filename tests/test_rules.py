"""Правила на эталонных событиях: match.jsonl срабатывает целиком, nomatch.jsonl — ни разу."""

import pytest

from tools.common import EVENTS, load_events, rule_files
from tools.harness import Harness

FILES = rule_files()
IDS = [rf.key for rf in FILES]


def _events(rf, name):
    path = EVENTS / rf.key / f"{name}.jsonl"
    assert path.is_file(), f"нет {path.relative_to(EVENTS.parent.parent)}"
    events = load_events(path)
    assert events, f"{path.name} пуст"
    return events


@pytest.mark.parametrize("rf", FILES, ids=IDS)
def test_match(rf):
    events = _events(rf, "match")
    harness = Harness(events)
    if rf.correlation:
        groups = {tuple(e.get(f) for f in rf.correlation.group_by) for e in harness.events}
        fired = harness.correlate(rf.correlation)
        assert set(fired) == groups, f"сработали группы {sorted(fired)}, ожидались {sorted(groups)}"
    else:
        matched = harness.match(rf.primary)
        missed = [events[i]["_test"] for i in range(len(events)) if i not in matched]
        assert not missed, f"не сработало на: {missed}"


@pytest.mark.parametrize("rf", FILES, ids=IDS)
def test_nomatch(rf):
    events = _events(rf, "nomatch")
    harness = Harness(events)
    if rf.correlation:
        fired = harness.correlate(rf.correlation)
        assert not fired, f"лишние срабатывания: {fired}"
    else:
        matched = harness.match(rf.primary)
        assert not matched, f"лишние срабатывания: {[events[i]['_test'] for i in matched]}"


def test_rule_files_have_unique_keys_and_ids():
    keys = [rf.key for rf in FILES]
    assert len(keys) == len(set(keys))
    ids = [str(r.id) for rf in FILES for r in rf.collection.rules]
    assert len(ids) == len(set(ids))


def test_no_orphan_event_directories():
    dirs = {p.name for p in EVENTS.iterdir() if p.is_dir()}
    assert dirs == set(IDS)
