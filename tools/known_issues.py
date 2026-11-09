"""Известные расхождения запросов из conversions/ с эталонными событиями в движках SIEM.

Каждая запись найдена прогоном tools.siem_it и объяснена. Проверка не падает на таких случаях,
но падает, если случай неожиданно прошёл: тогда запись устарела (например, исправлен бэкенд).
Для дефектов бэкенда задана правка запроса (fix: заменить подстроку): исправленный запрос
обязан пройти — так в CI подтверждается, что дефект именно в этом месте.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Known:
    engine: str
    language: str
    rule: str
    strings: tuple[str, ...]
    kind: str
    reason: str
    fix: tuple[str, str] | None = None


_BOOL_EQL = (
    "бэкенд EQL сравнивает логическое поле оператором «:», а Elasticsearch принимает «:» только "
    "для строк и предлагает «==» (HTTP 400)"
)
_SEQ_EQL = (
    "бэкенд EQL дописывает к последовательности «by  with runs=2» с пустым полем, и запрос не "
    "разбирается (HTTP 400)"
)
_CASE_LUCENE = (
    "в поле keyword без нормализатора запрос Lucene с подстановкой чувствителен к регистру, а "
    "правило Sigma — нет: «grep -i issecret» не находится; с нормализатором lowercase находится"
)

KNOWN: tuple[Known, ...] = (
    Known("elasticsearch", "eql", "github_pull_request_target_run_public_repo", ("keyword", "lowercase"),
          "backend", _BOOL_EQL, ("public_repo:true", "public_repo == true")),
    Known("elasticsearch", "eql", "github_runner_group_allows_public_repos", ("keyword", "lowercase"),
          "backend", _BOOL_EQL, ("runner_group_allow_public:true", "runner_group_allow_public == true")),
    Known("elasticsearch", "eql", "github_self_hosted_runner_registered_public_repo", ("keyword", "lowercase"),
          "backend", _BOOL_EQL, ("public_repo:true", "public_repo == true")),
    Known("elasticsearch", "eql", "github_pull_request_target_then_workflow_dispatch", ("keyword", "lowercase"),
          "backend", _SEQ_EQL, (" by  with runs=2", "")),
    Known("opensearch", "lucene", "proc_creation_lnx_runner_secret_marker_search", ("keyword",),
          "mapping", _CASE_LUCENE),
    Known("elasticsearch", "lucene", "proc_creation_lnx_runner_secret_marker_search", ("keyword",),
          "mapping", _CASE_LUCENE),
)


def lookup(engine: str, language: str, rule: str, strings: str) -> Known | None:
    for k in KNOWN:
        if (k.engine, k.language, k.rule) == (engine, language, rule) and strings in k.strings:
            return k
    return None
