"""Правила и эталонные события ссылаются только на задокументированные события и поля."""

from tools.catalog import problems


def test_catalog():
    found = problems()
    assert not found, "\n".join(found)
