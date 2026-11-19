"""Documentation stays in sync with the code."""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
DOCS = {
    "README.md": "🇹🇷 [Türkçe](README.tr.md)",
    "README.tr.md": "🇬🇧 [English](README.md)",
    "docs/GUIDE.md": "🇹🇷 [Türkçe](REHBER.tr.md)",
    "docs/REHBER.tr.md": "🇬🇧 [English](GUIDE.md)",
}


@pytest.mark.parametrize("doc,switch", DOCS.items())
def test_language_switch_under_title(doc, switch):
    lines = (ROOT / doc).read_text(encoding="utf-8").splitlines()
    assert lines[0].startswith("# ")
    assert switch in lines[1:4]


@pytest.mark.parametrize("doc", ["README.md", "README.tr.md"])
def test_every_toggle_is_documented_in_readme(doc):
    defaults = yaml.safe_load((ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8"))
    text = (ROOT / doc).read_text(encoding="utf-8")
    toggles = [k for k in defaults if k.endswith("_apply")] + ["accounts_lock_system_shells", "firewall_allowed_ports"]
    missing = [t for t in toggles if f"`{t}`" not in text]
    assert not missing, f"{doc} does not mention: {missing}"


@pytest.mark.parametrize("doc", list(DOCS))
def test_relative_links_exist(doc):
    path = ROOT / doc
    for target in re.findall(r"\]\(([^)#:]+)(?:#[^)]*)?\)", path.read_text(encoding="utf-8")):
        assert (path.parent / target).exists(), f"{doc}: broken link {target}"


@pytest.mark.parametrize("doc", ["README.md", "README.tr.md"])
def test_results_are_placeholders_not_invented(doc):
    text = (ROOT / doc).read_text(encoding="utf-8")
    block = text.split("<!-- RESULTS:START")[1].split("<!-- RESULTS:END")[0]
    assert "_TBD_" in block
    assert not re.search(r"\|\s*\d+\s*\|", block), "results table must be filled by scripts/compare_lynis.py"


def test_makefile_targets_match_docs():
    makefile = (ROOT / "Makefile").read_text(encoding="utf-8")
    targets = set(re.findall(r"^([a-z][a-z0-9-]+):", makefile, re.MULTILINE))
    # "make <target>" at the start of a command line or inside `backticks`
    usage = re.compile(r"(?:^\s*|`)make ([a-z][a-z0-9-]+)", re.MULTILINE)
    for doc in DOCS:
        for used in usage.findall((ROOT / doc).read_text(encoding="utf-8")):
            if used.endswith("-"):  # the generic "make apply-<category>" pattern
                continue
            assert used in targets, f"{doc} uses unknown target 'make {used}'"
