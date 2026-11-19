"""Shared test helpers: import paths and an Ansible-like Jinja2 environment."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import jinja2
import pytest

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"

sys.path.insert(0, str(ROOT / "filter_plugins"))
sys.path.insert(0, str(ROOT / "scripts"))

import hardening_filters  # noqa: E402


def _ansible_bool(value):
    """Mimic Ansible's ``bool`` filter."""
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y", "t"}


@pytest.fixture
def jinja_env():
    """Jinja2 environment configured like Ansible's template module.

    StrictUndefined makes a typo in a template variable fail the test instead
    of silently rendering an empty string.
    """
    env = jinja2.Environment(
        trim_blocks=True,
        lstrip_blocks=False,
        keep_trailing_newline=True,
        undefined=jinja2.StrictUndefined,
        extensions=["jinja2.ext.do", "jinja2.ext.loopcontrols"],
    )
    env.filters.update(hardening_filters.FilterModule().filters())
    env.filters["bool"] = _ansible_bool
    env.filters["to_json"] = lambda v: json.dumps(v)
    env.filters["to_nice_json"] = lambda v: json.dumps(v, indent=4, sort_keys=True)
    return env


@pytest.fixture
def render(jinja_env):
    def _render(relpath: str, **variables) -> str:
        source = (ROOT / relpath).read_text(encoding="utf-8")
        variables.setdefault("ansible_managed", "Ansible managed: do not edit by hand")
        return jinja_env.from_string(source).render(**variables)

    return _render


@pytest.fixture
def ss_output() -> str:
    return (FIXTURES / "ss-mailserver.txt").read_text(encoding="utf-8")
