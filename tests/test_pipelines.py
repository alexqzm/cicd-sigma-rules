"""Конвейер полей для KUMA загружается pySigma и переименовывает поля правил GitHub."""

from pathlib import Path

from sigma.backends.sqlite import sqliteBackend
from sigma.processing.pipeline import ProcessingPipeline

from tools.common import ROOT, rule_files

PIPELINE = ROOT / "pipelines" / "kuma-github-audit.yml"
RAW_FIELDS = ("action", "actor", "repo", "event", "public_repo", "runner_group_allow_public", "org")


def _pipeline():
    return ProcessingPipeline.from_yaml(Path(PIPELINE).read_text(encoding="utf-8"))


def test_kuma_pipeline_maps_github_fields():
    for rf in rule_files():
        if rf.logsource[0] != "github":
            continue
        sql = sqliteBackend(processing_pipeline=_pipeline()).convert(rf.collection)[0]
        assert "DeviceVendor='GitHub'" in sql and "DeviceProduct='Audit log'" in sql, rf.key
        assert "DeviceAction" in sql, rf.key
        for field in RAW_FIELDS:
            assert f" {field} " not in sql and f"({field} " not in sql, (rf.key, field)


def test_kuma_pipeline_maps_correlation_group_by():
    rf = next(r for r in rule_files() if r.correlation)
    sql = sqliteBackend(processing_pipeline=_pipeline()).convert(rf.collection)[0]
    assert "GROUP BY DeviceCustomString1" in sql


def test_kuma_pipeline_leaves_process_creation_rules_alone():
    rf = next(r for r in rule_files() if r.logsource[2] == "process_creation")
    sql = sqliteBackend(processing_pipeline=_pipeline()).convert(rf.collection)[0]
    assert "DeviceVendor" not in sql and "CommandLine" in sql
