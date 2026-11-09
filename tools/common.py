"""Общие функции: пути репозитория, загрузка правил, эталонных событий и сопоставлений."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection
from sigma.correlations import SigmaCorrelationRule
from sigma.rule import SigmaDetection, SigmaDetectionItem, SigmaRule

ROOT = Path(__file__).resolve().parent.parent
RULES = ROOT / "rules"
EVENTS = ROOT / "tests" / "events"
CONVERSIONS = ROOT / "conversions"
MAPPINGS = ROOT / "mappings" / "mappings.yml"
CATALOG = ROOT / "data" / "github-audit-events.json"

#: ключ эталонного события с описанием случая; в журнал не попадает
TEST_KEY = "_test"


@dataclass
class RuleFile:
    """Файл правил: одно правило или корреляция вместе с базовыми правилами."""

    path: Path
    collection: SigmaCollection

    @property
    def key(self) -> str:
        return self.path.stem

    @property
    def rel(self) -> str:
        return self.path.relative_to(ROOT).as_posix()

    @property
    def correlation(self) -> SigmaCorrelationRule | None:
        for rule in self.collection.rules:
            if isinstance(rule, SigmaCorrelationRule):
                return rule
        return None

    @property
    def base_rules(self) -> list[SigmaRule]:
        return [r for r in self.collection.rules if isinstance(r, SigmaRule)]

    @property
    def primary(self) -> SigmaRule | SigmaCorrelationRule:
        """Правило, по которому срабатывает оповещение: корреляция, если она есть."""
        return self.correlation or self.base_rules[0]

    @property
    def logsource(self) -> tuple[str | None, str | None, str | None]:
        ls = self.base_rules[0].logsource
        return (ls.product, ls.service, ls.category)


def rule_files(root: Path = RULES) -> list[RuleFile]:
    out = []
    for path in sorted(root.rglob("*.yml")):
        collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
        collection.resolve_rule_references()
        out.append(RuleFile(path, collection))
    return out


def load_events(path: Path) -> list[dict]:
    """Эталонные события JSON Lines: одно событие в строке, пустые строки пропускаются."""
    events = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            events.append(json.loads(line))
    return events


def strip_test(event: dict) -> dict:
    return {k: v for k, v in event.items() if k != TEST_KEY}


def load_mappings() -> dict:
    return yaml.safe_load(MAPPINGS.read_text(encoding="utf-8"))


def load_catalog() -> dict:
    return json.loads(CATALOG.read_text(encoding="utf-8"))


def detection_selections(rule: SigmaRule) -> list[list[SigmaDetectionItem]]:
    """Наборы условий, связанных через И: элементы каждого SigmaDetection без вложенных ИЛИ."""
    out: list[list[SigmaDetectionItem]] = []

    def walk(det: SigmaDetection) -> None:
        items = [i for i in det.detection_items if isinstance(i, SigmaDetectionItem)]
        if items:
            out.append(items)
        for sub in det.detection_items:
            if isinstance(sub, SigmaDetection):
                walk(sub)

    for det in rule.detection.detections.values():
        walk(det)
    return out
