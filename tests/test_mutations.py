"""Мутационная проверка: эталонные события ловят ослабление условий правил.

Каждая мутация убирает из правила одно условие. Если после этого ни одно событие nomatch.jsonl
не срабатывает, эталонные события это условие не проверяют.
"""

import pytest
from sigma.collection import SigmaCollection

from tools.common import EVENTS, RULES, RuleFile, load_events
from tools.harness import Harness

MUTATIONS = [
    ("github/audit/github_pull_request_target_run_public_repo.yml",
     "        public_repo: true\n", ""),
    ("github/audit/github_self_hosted_runner_registered_public_repo.yml",
     "        public_repo: true\n", ""),
    ("github/audit/github_runner_group_allows_public_repos.yml",
     "        runner_group_allow_public: true\n", ""),
    ("github/audit/github_pull_request_target_run_public_repo.yml",
     "        action: 'workflows.created_workflow_run'\n", "        action|startswith: 'workflows.'\n"),
    ("github/correlation/github_pull_request_target_then_workflow_dispatch.yml",
     "type: temporal_ordered", "type: temporal"),
    ("github/correlation/github_pull_request_target_then_workflow_dispatch.yml",
     "    timespan: 1h", "    timespan: 2h"),
    ("github/correlation/github_pull_request_target_then_workflow_dispatch.yml",
     "    group-by:\n        - repo\n", "    group-by:\n        - org\n"),
    ("linux/process_creation/proc_creation_lnx_node_ai_cli_permission_bypass.yml",
     "condition: selection_parent and 1 of selection_cli_*", "condition: 1 of selection_cli_*"),
    ("linux/process_creation/proc_creation_lnx_node_ai_cli_permission_bypass.yml",
     "            - '--dangerously-skip-permissions'\n", ""),
    ("linux/process_creation/proc_creation_lnx_runner_secret_marker_search.yml",
     "condition: all of selection_search_* or selection_memdump",
     "condition: selection_search_marker or selection_memdump"),
    ("linux/process_creation/proc_creation_lnx_runner_secret_marker_search.yml",
     "        CommandLine|contains: 'memdump.py'", "        CommandLine|contains: 'memdump'"),
    ("linux/process_creation/proc_creation_lnx_ai_cli_permission_bypass.yml",
     "            - 'gemini'\n", ""),
]


@pytest.mark.parametrize("rel, old, new", MUTATIONS, ids=[f"{m[0].rsplit('/', 1)[1]}:{i}"
                                                          for i, m in enumerate(MUTATIONS)])
def test_mutation_is_caught(rel, old, new):
    path = RULES / rel
    text = path.read_text(encoding="utf-8")
    assert text.count(old) == 1, f"мутация не применима к {rel}"
    collection = SigmaCollection.from_yaml(text.replace(old, new))
    collection.resolve_rule_references()
    rf = RuleFile(path, collection)
    harness = Harness(load_events(EVENTS / rf.key / "nomatch.jsonl"))
    fired = harness.correlate(rf.correlation) if rf.correlation else harness.match(rf.primary)
    assert fired, "после мутации ни одно событие nomatch не срабатывает — условие не проверяется"
