"""Проверка правил валидаторами pySigma с закреплённой версией MITRE ATT&CK.

Валидатор тегов ATT&CK по умолчанию скачивает последнюю версию матрицы. Здесь он читает
закреплённый файл attack-stix-data, а хеш файла сверяется до загрузки: теги проверяются
против той версии ATT&CK, по которой они расставлены.

usage: python -m tools.check --attack enterprise-attack-20.1.json
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import tempfile
from pathlib import Path

from sigma.collection import SigmaCollection
from sigma.data import mitre_attack
from sigma.plugins import InstalledSigmaPlugins
from sigma.validation import SigmaValidator

from .common import RULES

ATTACK_VERSION = "20.1"
ATTACK_URL = (
    "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/"
    "a8db2f52eb933c9c99060c123e088b3326d3a607/enterprise-attack/enterprise-attack-20.1.json"
)
ATTACK_SHA256 = "539a843a7b53ed9749740b2123dddae3726b1a4831841c32aca740b011b910b5"

#: валидаторы, которые не применяются, и причины
EXCLUDED = {
}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack", type=Path, required=True,
                        help=f"enterprise-attack-{ATTACK_VERSION}.json ({ATTACK_URL})")
    args = parser.parse_args(argv)

    digest = hashlib.sha256(args.attack.read_bytes()).hexdigest()
    if digest != ATTACK_SHA256:
        print(f"{args.attack}: SHA-256 {digest}, ожидался {ATTACK_SHA256}")
        return 2
    cache = tempfile.TemporaryDirectory(prefix="pysigma-attack-")
    mitre_attack.set_cache_dir(cache.name)
    mitre_attack.set_url(str(args.attack))
    if mitre_attack.mitre_attack_version != ATTACK_VERSION:
        print(f"загружена ATT&CK {mitre_attack.mitre_attack_version}, ожидалась {ATTACK_VERSION}")
        return 2

    collection = SigmaCollection.load_ruleset([RULES], collect_errors=True)
    errors = [(rule, err) for rule in collection.rules for err in rule.errors]
    for rule, err in errors:
        print(f"ошибка разбора: {rule.source}: {err}")

    validators = InstalledSigmaPlugins.autodiscover().validators
    unknown = set(EXCLUDED) - set(validators)
    if unknown:
        print(f"неизвестные валидаторы в исключениях: {sorted(unknown)}")
        return 2
    used = {name: cls for name, cls in validators.items() if name not in EXCLUDED}
    issues = SigmaValidator(used.values()).validate_rules(collection.rules)
    for issue in issues:
        rules = ", ".join(str(r.source.path.relative_to(RULES.parent)) if r.source else str(r.id)
                          for r in issue.rules)
        print(f"{issue.severity.name}: {type(issue).__name__}: {issue.description} — {rules}")
    print(f"правил: {len(collection.rules)}, валидаторов: {len(used)} (ATT&CK {ATTACK_VERSION}), "
          f"ошибок разбора: {len(errors)}, замечаний: {len(issues)}")
    for name, reason in sorted(EXCLUDED.items()):
        print(f"  не применяется {name}: {reason}")
    cache.cleanup()
    return 1 if errors or issues else 0


if __name__ == "__main__":
    sys.exit(main())
