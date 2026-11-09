"""Каталог событий журнала аудита GitHub по документации GitHub (github/docs, src/audit-logs/data).

Правила и эталонные события должны ссылаться только на задокументированные события и поля:
каталог хранит события, которые встречаются в репозитории, с полями из документации, и поля,
общие для всех событий.

usage:
  python -m tools.catalog sync DOCS_CHECKOUT  # обновить data/github-audit-events.json
  python -m tools.catalog check               # проверить правила и события по каталогу
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

from .common import CATALOG, EVENTS, TEST_KEY, detection_selections, load_catalog, load_events, rule_files

SOURCES = ("fpt/organization.json", "ghec/organization.json", "ghec/enterprise.json")
DOCS_DATA = Path("src/audit-logs/data")

#: поля событий process_creation, которые используют эталонные события (таксономия SigmaHQ)
PROCESS_FIELDS = {
    "@timestamp", "ProcessId", "Image", "CommandLine", "CurrentDirectory", "User",
    "ParentProcessId", "ParentImage", "ParentCommandLine",
}


def _github_rule_files():
    return [rf for rf in rule_files() if rf.logsource[0] == "github"]


def referenced_actions() -> set[str]:
    actions: set[str] = set()
    for rf in _github_rule_files():
        for rule in rf.base_rules:
            for items in detection_selections(rule):
                for item in items:
                    if item.field == "action":
                        actions.update(str(v) for v in item.value)
        for path in sorted((EVENTS / rf.key).glob("*.jsonl")):
            actions.update(e["action"] for e in load_events(path))
    return actions


def sync(docs: Path) -> dict:
    fields: dict[str, set[str]] = {}
    for name in SOURCES:
        for entry in json.loads((docs / DOCS_DATA / name).read_text(encoding="utf-8")):
            fields.setdefault(entry["action"], set()).update(entry.get("fields", []))
    common = set.intersection(*fields.values())
    wanted = referenced_actions()
    missing = sorted(wanted - fields.keys())
    if missing:
        raise SystemExit(f"нет в документации: {', '.join(missing)}")

    def git(*args):
        return subprocess.run(["git", "-C", str(docs), *args], check=True, capture_output=True,
                              text=True).stdout.strip()

    return {
        "source": {
            "repository": "https://github.com/github/docs",
            "commit": git("rev-parse", "HEAD"),
            "date": git("log", "-1", "--format=%cs"),
            "files": [f"{DOCS_DATA.as_posix()}/{n}" for n in SOURCES],
            "note": "Event and field names from the GitHub audit log event documentation; "
                    "only events referenced by rules or test events are kept.",
        },
        "common_fields": sorted(common),
        "actions": {a: sorted(fields[a] - common) for a in sorted(wanted)},
    }


def problems() -> list[str]:
    catalog = load_catalog()
    common = set(catalog["common_fields"])
    actions = {a: set(f) | common for a, f in catalog["actions"].items()}
    out: list[str] = []
    for rf in rule_files():
        product = rf.logsource[0]
        if product == "github":
            for rule in rf.base_rules:
                for items in detection_selections(rule):
                    acts = [str(v) for i in items if i.field == "action" for v in i.value]
                    if not acts:
                        out.append(f"{rf.rel}: «{rule.title}»: условие без поля action")
                        continue
                    for act in acts:
                        if act not in actions:
                            out.append(f"{rf.rel}: событие {act} не задокументировано")
                            continue
                        for item in items:
                            if item.field not in actions[act]:
                                out.append(f"{rf.rel}: у события {act} нет поля {item.field}")
            if rf.correlation:
                for field in rf.correlation.group_by or []:
                    if field not in common:
                        out.append(f"{rf.rel}: поле группировки {field} есть не у всех событий")
        for path in sorted((EVENTS / rf.key).glob("*.jsonl")):
            rel = path.relative_to(EVENTS.parent.parent).as_posix()
            for n, event in enumerate(load_events(path), 1):
                if not event.get(TEST_KEY):
                    out.append(f"{rel}:{n}: нет описания случая {TEST_KEY}")
                keys = set(event) - {TEST_KEY}
                if product == "github":
                    act = event.get("action")
                    if act not in actions:
                        out.append(f"{rel}:{n}: событие {act} не задокументировано")
                        continue
                    for key in sorted(keys - actions[act]):
                        out.append(f"{rel}:{n}: у события {act} нет поля {key}")
                elif rf.logsource[2] == "process_creation":
                    for key in sorted(keys - PROCESS_FIELDS):
                        out.append(f"{rel}:{n}: поле {key} вне набора полей process_creation")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="cmd", required=True)
    p_sync = sub.add_parser("sync", help="обновить каталог по клону github/docs")
    p_sync.add_argument("docs", type=Path)
    sub.add_parser("check", help="проверить правила и события по каталогу")
    args = parser.parse_args(argv)
    if args.cmd == "sync":
        data = sync(args.docs)
        CATALOG.parent.mkdir(parents=True, exist_ok=True)
        CATALOG.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        print(f"{CATALOG.name}: {len(data['actions'])} событий, документация {data['source']['commit'][:12]}")
        return 0
    found = problems()
    for line in found:
        print(line)
    print(f"нарушений: {len(found)}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
