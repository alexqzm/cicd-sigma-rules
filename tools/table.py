"""Таблица правил docs/rules.md: уровень, источник событий, ATT&CK, инциденты, OWASP, ГОСТ.

Таблица собирается из правил, сопоставлений mappings/mappings.yml, эталонных событий и
conversions/. Имена техник ATT&CK берутся из закреплённого файла attack-stix-data.

usage: python -m tools.table --attack enterprise-attack-20.1.json [--atlas DIR] [--check]
  --atlas — клон cps-supply-chain-atlas: проверить, что упомянутые записи атласа существуют
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .common import CONVERSIONS, EVENTS, ROOT, load_events, load_mappings, rule_files
from .convert import TARGETS
from .known_issues import KNOWN

OUT = ROOT / "docs" / "rules.md"

OWASP = {
    "CICD-SEC-1": "Insufficient Flow Control Mechanisms",
    "CICD-SEC-2": "Inadequate Identity and Access Management",
    "CICD-SEC-3": "Dependency Chain Abuse",
    "CICD-SEC-4": "Poisoned Pipeline Execution (PPE)",
    "CICD-SEC-5": "Insufficient PBAC (Pipeline-Based Access Controls)",
    "CICD-SEC-6": "Insufficient Credential Hygiene",
    "CICD-SEC-7": "Insecure System Configuration",
    "CICD-SEC-8": "Ungoverned Usage of 3rd Party Services",
    "CICD-SEC-9": "Improper Artifact Integrity Validation",
    "CICD-SEC-10": "Insufficient Logging and Visibility",
}

#: названия процессов ГОСТ Р 56939-2024 (подразделы 5.x), на которые ссылаются сопоставления
GOST = {
    "5.4": "Управление конфигурацией программного обеспечения",
    "5.9": "Экспертиза исходного кода",
    "5.12": "Использование безопасной системы сборки программного обеспечения",
    "5.13": "Обеспечение безопасности сборочной среды программного обеспечения",
    "5.14": "Управление доступом и контроль целостности кода при разработке программного обеспечения",
    "5.15": "Обеспечение безопасности используемых секретов",
    "5.16": "Использование инструментов композиционного анализа",
    "5.17": "Проверка кода на предмет внедрения вредоносного программного обеспечения через цепочки поставок",
    "5.20": "Обеспечение безопасности при выпуске готовой к эксплуатации версии программного обеспечения",
    "5.21": "Безопасная поставка программного обеспечения пользователям",
}

_FOLDER = {("opensearch", "lucene"): "opensearch", ("elasticsearch", "lucene"): "elasticsearch",
           ("elasticsearch", "eql"): "elasticsearch-eql"}

LEVEL_RU = {"informational": "инф.", "low": "низкий", "medium": "средний", "high": "высокий",
            "critical": "критический"}


def attack_names(path: Path) -> dict[str, str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    names = {}
    for obj in data["objects"]:
        if obj.get("type") in ("attack-pattern", "x-mitre-tactic") and not obj.get("revoked"):
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    key = obj["x_mitre_shortname"] if obj["type"] == "x-mitre-tactic" else ref["external_id"]
                    names[key.lower()] = obj["name"]
    return names


def problems(mappings: dict, atlas: Path | None) -> list[str]:
    out = []
    keys = {rf.key for rf in rule_files()}
    rules = mappings.get("rules", {})
    out += [f"нет сопоставления для {k}" for k in sorted(keys - rules.keys())]
    out += [f"сопоставление без правила: {k}" for k in sorted(rules.keys() - keys)]
    for key, m in rules.items():
        if set(m) != {"incidents", "owasp_cicd", "gost_56939"}:
            out.append(f"{key}: поля {sorted(m)}")
            continue
        out += [f"{key}: неизвестный риск OWASP {r}" for r in m["owasp_cicd"] if r not in OWASP]
        out += [f"{key}: нет процесса ГОСТ {p} в справочнике" for p in m["gost_56939"] if p not in GOST]
        if atlas is not None:
            out += [f"{key}: нет записи атласа {i}" for i in m["incidents"]
                    if not (atlas / "data" / "records" / f"{i}.yaml").is_file()]
    return out


def render(names: dict[str, str], mappings: dict) -> str:
    atlas = mappings["atlas"].rstrip("/")
    rows = []
    for rf in rule_files():
        rule = rf.primary
        m = mappings["rules"][rf.key]
        product, service, category = rf.logsource
        source = "/".join(x for x in (product, service or category) if x)
        if rf.correlation:
            source += ", корреляция"
        tags = []
        for tag in rule.tags:
            if tag.namespace != "attack":
                continue
            name = names.get(tag.name, "?")
            if tag.name.startswith("t"):
                tid = tag.name.upper()
                url = "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"
                tags.append(f"[{tid}]({url}) {name}")
        incidents = ", ".join(f"[{i}]({atlas}/blob/main/data/records/{i}.yaml)" for i in m["incidents"]) or "—"
        n_match = len(load_events(EVENTS / rf.key / "match.jsonl"))
        n_nomatch = len(load_events(EVENTS / rf.key / "nomatch.jsonl"))
        flagged = {_FOLDER[(k.engine, k.language)] for k in KNOWN if k.rule == rf.key}
        targets = [t.name + ("*" if t.name in flagged else "") for t in TARGETS
                   if (CONVERSIONS / t.name / f"{rf.key}.{t.ext}").is_file()]
        rows.append(
            f"| [{rule.title}](../{rf.rel}) | {LEVEL_RU[rule.level.name.lower()]} | {source} | "
            f"{'<br>'.join(tags)} | {incidents} | {', '.join(m['owasp_cicd'])} | "
            f"{', '.join(m['gost_56939'])} | {n_match} / {n_nomatch} | {', '.join(targets)} |"
        )
    used_owasp = sorted({r for m in mappings["rules"].values() for r in m["owasp_cicd"]},
                        key=lambda r: int(r.rsplit("-", 1)[1]))
    used_gost = sorted({p for m in mappings["rules"].values() for p in m["gost_56939"]},
                       key=lambda p: tuple(int(x) for x in p.split(".")))
    lines = [
        "# Правила",
        "",
        "Сгенерировано `python -m tools.table` из правил, `mappings/mappings.yml`, эталонных событий",
        "и `conversions/`; вручную не правится. Сопоставления с инцидентами, OWASP и ГОСТ — оценка",
        "автора; теги ATT&CK — по версии " + names.get("__version__", "") + ".",
        "",
        "| Правило | Уровень | Источник | ATT&CK | Инциденты (атлас) | OWASP CI/CD | ГОСТ Р 56939-2024 | "
        "Эталонные события (match / nomatch) | Запросы |",
        "|---|---|---|---|---|---|---|---|---|",
        *rows,
        "",
        "\\* Запрос этой цели расходится с эталонными событиями в движке SIEM (дефект бэкенда или",
        "зависимость от хранения строк) — см. [известные расхождения](../conversions/README.md#проверка-в-движках).",
        "",
        "## OWASP Top 10 CI/CD Security Risks",
        "",
        *[f"- **{r}** — {OWASP[r]}" for r in used_owasp],
        "",
        "## Процессы ГОСТ Р 56939-2024",
        "",
        *[f"- **{p}** — {GOST[p]}" for p in used_gost],
        "",
    ]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--attack", type=Path, required=True)
    parser.add_argument("--atlas", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)
    mappings = load_mappings()
    found = problems(mappings, args.atlas)
    for line in found:
        print(line)
    if found:
        return 1
    names = attack_names(args.attack)
    data = json.loads(args.attack.read_text(encoding="utf-8"))
    version = next(o["x_mitre_version"] for o in data["objects"] if o["type"] == "x-mitre-collection")
    names["__version__"] = f"ATT&CK {version}"
    text = render(names, mappings)
    if args.check:
        same = OUT.is_file() and OUT.read_text(encoding="utf-8") == text
        print("docs/rules.md " + ("совпадает" if same else "расходится с правилами"))
        return 0 if same else 1
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(text, encoding="utf-8")
    print(f"записано: {OUT.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
