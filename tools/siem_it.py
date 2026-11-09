"""Интеграционная проверка запросов из conversions/ в OpenSearch и Elasticsearch.

Для каждого правила эталонные события (match и nomatch) индексируются в отдельный индекс, и
запрос из conversions/ исполняется движком: Lucene через query_string, в Elasticsearch ещё и
EQL через _eql/search. Запрос должен найти все события match и ни одного события nomatch; для
корреляции — последовательность в каждой группе match и ни одной в nomatch.

Строковые поля индексируются как keyword. Режим --strings lowercase добавляет нормализатор
lowercase: так в индексе хранят строки, когда нужен поиск без учёта регистра.

Известные расхождения перечислены в tools/known_issues.py с причиной: такой случай не роняет
проверку, а неожиданный успех в нём — роняет, чтобы список не устаревал.

usage: python -m tools.siem_it --engine opensearch --url http://localhost:9200 [--report FILE]
"""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request

from .common import CONVERSIONS, EVENTS, load_events, rule_files, strip_test
from .known_issues import lookup



class Engine:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(self, method: str, path: str, body=None, ndjson: str | None = None):
        data, ctype = None, "application/json"
        if ndjson is not None:
            data, ctype = ndjson.encode(), "application/x-ndjson"
        elif body is not None:
            data = json.dumps(body).encode()
        req = urllib.request.Request(self.url + path, data=data, method=method,
                                     headers={"Content-Type": ctype})
        try:
            with self.opener.open(req, timeout=60) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            return exc.code, json.loads(exc.read() or b"{}")

    def info(self) -> str:
        _, body = self.call("GET", "/")
        ver = body.get("version", {})
        return f"{ver.get('distribution', 'elasticsearch')} {ver.get('number')}"


def mapping(strings: str) -> dict:
    keyword = {"type": "keyword"}
    settings = {"number_of_shards": 1, "number_of_replicas": 0}
    if strings == "lowercase":
        keyword["normalizer"] = "lc"
        settings["analysis"] = {"normalizer": {"lc": {"type": "custom", "filter": ["lowercase"]}}}
    return {
        "settings": settings,
        "mappings": {
            "dynamic_templates": [{"strings": {"match_mapping_type": "string", "mapping": keyword}}],
            "properties": {"@timestamp": {"type": "date", "format": "epoch_millis"}},
        },
    }


def load_index(engine: Engine, index: str, strings: str, docs: dict[str, dict]) -> None:
    engine.call("DELETE", f"/{index}")
    status, body = engine.call("PUT", f"/{index}", mapping(strings))
    if status != 200:
        raise RuntimeError(f"создание индекса {index}: {status} {body}")
    lines = []
    for doc_id, doc in docs.items():
        lines.append(json.dumps({"index": {"_index": index, "_id": doc_id}}))
        lines.append(json.dumps(doc))
    status, body = engine.call("POST", "/_bulk?refresh=true", ndjson="\n".join(lines) + "\n")
    if status != 200 or body.get("errors"):
        raise RuntimeError(f"загрузка {index}: {status} {json.dumps(body)[:500]}")


def lucene_hits(engine: Engine, index: str, query: str) -> tuple[set[str] | None, str]:
    status, body = engine.call("POST", f"/{index}/_search",
                               {"query": {"query_string": {"query": query}}, "size": 1000})
    if status != 200:
        return None, f"HTTP {status}: {_reason(body)}"
    return {h["_id"] for h in body["hits"]["hits"]}, ""


def eql_hits(engine: Engine, index: str, query: str) -> tuple[list[list[str]] | None, str]:
    status, body = engine.call("POST", f"/{index}/_eql/search", {"query": query, "size": 1000})
    if status != 200:
        return None, f"HTTP {status}: {_reason(body)}"
    hits = body["hits"]
    if "sequences" in hits:
        return [[e["_id"] for e in s["events"]] for s in hits["sequences"]], ""
    return [[e["_id"]] for e in hits.get("events", [])], ""


def _reason(body: dict) -> str:
    err = body.get("error", {})
    if isinstance(err, dict):
        root = (err.get("root_cause") or [{}])[0]
        return (root.get("reason") or err.get("reason") or str(err))[:300]
    return str(err)[:300]


def evaluate(engine: Engine, index: str, lang: str, query: str, rf, docs: dict, match: list[dict]):
    """(совпало ли с ожиданием, найденное, ошибка движка)."""
    want = {d for d in docs if d.startswith("match-")}
    if rf.correlation:
        if lang != "eql":
            return False, None, "не поддерживается"
        group_by = rf.correlation.group_by
        groups = {tuple(strip_test(e).get(f) for f in group_by) for e in match}
        seqs, error = eql_hits(engine, index, query)
        if seqs is None:
            return False, None, error
        fired = {tuple(docs[s[0]].get(f) for f in group_by) for s in seqs}
        stray = {i for s in seqs for i in s if i.startswith("nomatch-")}
        return fired == groups and not stray, sorted(" → ".join(s) for s in seqs), ""
    if lang == "eql":
        seqs, error = eql_hits(engine, index, query)
        found = None if seqs is None else {s[0] for s in seqs}
    else:
        found, error = lucene_hits(engine, index, query)
    return found == want, None if found is None else sorted(found), error


def run(engine_name: str, url: str, strings: str) -> tuple[list[dict], str]:
    engine = Engine(url)
    version = engine.info()
    results = []
    languages = [("lucene", engine_name, "lucene")]
    if engine_name == "elasticsearch":
        languages.append(("eql", "elasticsearch-eql", "eql"))
    for rf in rule_files():
        match = load_events(EVENTS / rf.key / "match.jsonl")
        nomatch = load_events(EVENTS / rf.key / "nomatch.jsonl")
        docs = {f"match-{i}": strip_test(e) for i, e in enumerate(match, 1)}
        docs.update({f"nomatch-{i}": strip_test(e) for i, e in enumerate(nomatch, 1)})
        index = f"csr-{rf.key.replace('_', '-')}"
        loaded = False
        for lang, folder, ext in languages:
            path = CONVERSIONS / folder / f"{rf.key}.{ext}"
            if not path.is_file():
                continue
            if not loaded:
                load_index(engine, index, strings, docs)
                loaded = True
            query = path.read_text(encoding="utf-8").strip()
            ok, got, error = evaluate(engine, index, lang, query, rf, docs, match)
            known = lookup(engine_name, lang, rf.key, strings)
            fixed = None
            if known and known.fix:
                old, new = known.fix
                if old not in query:
                    fixed = f"в запросе нет «{old}»"
                else:
                    fixed_ok, fixed_got, fixed_error = evaluate(
                        engine, index, lang, query.replace(old, new), rf, docs, match)
                    fixed = True if fixed_ok else f"не прошёл: {fixed_error or fixed_got}"
            results.append({
                "rule": rf.key, "language": lang, "ok": ok, "known": known.reason if known else None,
                "fix": list(known.fix) if known and known.fix else None, "fixed": fixed,
                "error": error, "got": got, "expected": sorted(d for d in docs if d.startswith("match-")),
            })
        if loaded:
            engine.call("DELETE", f"/{index}")
    return results, version


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--engine", choices=("opensearch", "elasticsearch"), required=True)
    parser.add_argument("--url", required=True)
    parser.add_argument("--strings", choices=("keyword", "lowercase"), default="keyword")
    parser.add_argument("--report", help="дописать таблицу результатов в этот файл (Markdown)")
    args = parser.parse_args(argv)
    results, version = run(args.engine, args.url, args.strings)
    unexpected = [r for r in results
                  if r["ok"] == bool(r["known"]) or (r["fix"] and r["fixed"] is not True)]
    rows = [f"### {version}, строки: {args.strings}", "", "| Правило | Запрос | Итог |", "|---|---|---|"]
    for r in results:
        if r["ok"] and not r["known"]:
            verdict = "совпало с ожиданием"
        elif r["ok"]:
            verdict = f"**неожиданно совпало** (в known_issues: {r['known']})"
        elif r["known"]:
            verdict = f"известное расхождение: {r['known']}"
            if r["fix"]:
                fixed = "прошёл" if r["fixed"] is True else f"**{r['fixed']}**"
                verdict += f"; запрос с правкой «{r['fix'][0]}» → «{r['fix'][1]}» {fixed}"
        else:
            verdict = f"**расхождение**: {r['error'] or 'найдено ' + json.dumps(r['got'])}"
        rows.append(f"| `{r['rule']}` | {r['language']} | {verdict} |")
    rows += ["", f"Проверено запросов: {len(results)}, неожиданных исходов: {len(unexpected)}.", ""]
    text = "\n".join(rows)
    print(text)
    for r in unexpected:
        print(json.dumps(r, ensure_ascii=False))
    if args.report:
        with open(args.report, "a", encoding="utf-8") as fh:
            fh.write(text + "\n")
    return 1 if unexpected else 0


if __name__ == "__main__":
    sys.exit(main())
