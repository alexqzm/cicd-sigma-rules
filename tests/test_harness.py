"""Семантика корреляций в стенде на маленьких синтетических правилах."""

import pytest
from sigma.collection import SigmaCollection

from tools.harness import Harness

RULES = """
title: A
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a01
name: rule_a
status: experimental
logsource: {product: test}
detection:
    selection: {kind: a}
    condition: selection
level: low
---
title: B
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a02
name: rule_b
status: experimental
logsource: {product: test}
detection:
    selection: {kind: b}
    condition: selection
level: low
---
title: A then B
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a03
status: experimental
correlation:
    type: {type}
    rules: [rule_a, rule_b]
    group-by: [host]
    timespan: 10m
level: low
"""

MIN = 60_000


def _corr(kind):
    collection = SigmaCollection.from_yaml(RULES.replace("{type}", kind))
    collection.resolve_rule_references()
    return collection.rules[-1]


def _ev(kind, minute, host="h1"):
    return {"@timestamp": minute * MIN, "kind": kind, "host": host}


@pytest.mark.parametrize("events, ordered, unordered", [
    ([_ev("a", 0), _ev("b", 5)], True, True),
    ([_ev("b", 0), _ev("a", 5)], False, True),
    ([_ev("a", 0), _ev("b", 11)], False, False),
    ([_ev("a", 0), _ev("b", 10)], True, True),
    ([_ev("a", 0), _ev("b", 5, host="h2")], False, False),
    ([_ev("a", 0), _ev("a", 30), _ev("b", 35)], True, True),
    ([_ev("b", 0), _ev("a", 1), _ev("b", 12)], False, True),
    ([_ev("a", 0)], False, False),
])
def test_temporal_semantics(events, ordered, unordered):
    harness = Harness(events)
    assert bool(harness.correlate(_corr("temporal_ordered"))) is ordered
    assert bool(harness.correlate(_corr("temporal"))) is unordered


def test_bool_and_missing_fields():
    collection = SigmaCollection.from_yaml("""
title: Flag
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a04
status: experimental
logsource: {product: test}
detection:
    selection: {flag: true, absent_field: x}
    condition: selection
level: low
""")
    harness = Harness([{"flag": True}, {"flag": False}])
    assert harness.match(collection.rules[0]) == []
    collection = SigmaCollection.from_yaml("""
title: Flag
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a05
status: experimental
logsource: {product: test}
detection:
    selection: {flag: true}
    condition: selection
level: low
""")
    assert harness.match(collection.rules[0]) == [0]


def test_case_insensitive_strings():
    collection = SigmaCollection.from_yaml("""
title: Case
id: 6d0c8a52-0a8e-4c4e-9f0e-3f3e1f6b0a06
status: experimental
logsource: {product: test}
detection:
    selection: {CommandLine|contains: 'isSecret'}
    condition: selection
level: low
""")
    harness = Harness([{"CommandLine": "grep ISSECRET x"}, {"CommandLine": "grep issecret"}, {"CommandLine": "x"}])
    assert harness.match(collection.rules[0]) == [0, 1]
