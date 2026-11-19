"""scripts/lynis_report.py and scripts/compare_lynis.py"""

import json
from pathlib import Path

import compare_lynis
import lynis_report

FIX = Path(__file__).resolve().parent / "fixtures"
BEFORE = FIX / "lynis-before.dat"
AFTER = FIX / "lynis-after.dat"


def test_parse_report_fields():
    r = lynis_report.load_report(BEFORE)
    assert r["hardening_index"] == 58
    assert r["lynis_version"] == "3.0.9"
    assert r["hostname"] == "testhost"
    assert r["os"] == "Ubuntu 24.04.1 LTS"
    assert r["tests_done"] == 258
    assert r["warning_count"] == 3
    assert r["suggestion_count"] == 9
    w = r["warnings"][2]
    assert w == {
        "test_id": "SSH-7408",
        "message": "Root can directly login via SSH",
        "details": "PermitRootLogin",
        "solution": "",
    }
    hrdn = r["suggestions"][-1]
    assert hrdn["solution"].startswith("Install a tool like rkhunter")


def test_incomplete_report_does_not_crash():
    r = lynis_report.load_report(FIX / "lynis-incomplete.dat")
    assert r["hardening_index"] is None
    assert r["warnings"][0]["test_id"] == "only-two-fields"
    assert r["warnings"][0]["details"] == ""


def test_markdown_output():
    md = lynis_report.to_markdown(lynis_report.load_report(BEFORE))
    assert "**Hardening index: 58 / 100**" in md
    assert "| PKGS-7392 | Found one or more vulnerable packages. |  |" in md


def test_cli_json(tmp_path, capsys):
    out = tmp_path / "r.json"
    assert lynis_report.main([str(BEFORE), "--format", "json", "-o", str(out)]) == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["hardening_index"] == 58


def test_cli_missing_file(capsys):
    assert lynis_report.main(["/nonexistent/report.dat"]) == 2
    assert "not found" in capsys.readouterr().err


def test_compare_numbers():
    res = compare_lynis.compare(lynis_report.load_report(BEFORE), lynis_report.load_report(AFTER))
    assert res["hardening_index"] == {"before": 58, "after": 67, "delta": "+9"}
    assert res["warnings"] == {"before": 3, "after": 1, "delta": "-2"}
    assert res["suggestions"]["delta"] == "-6"
    assert ("SSH-7408", "Root can directly login via SSH") in res["resolved_warnings"]
    assert res["new_warnings"] == []
    assert [s[0] for s in res["new_suggestions"]] == ["BANN-7126"]


def test_compare_markdown_is_readme_ready():
    res = compare_lynis.compare(lynis_report.load_report(BEFORE), lynis_report.load_report(AFTER))
    md = compare_lynis.to_markdown(res)
    lines = md.splitlines()
    assert lines[1] == "| Metric | Before | After | Change |"
    assert "| **Lynis hardening index** | 58 | 67 | **+9** |" in md
    assert "**Resolved warnings** (2)" in md
    assert "different Lynis versions" not in md


def test_compare_flags_version_mismatch_and_missing_index(tmp_path, capsys):
    inc = FIX / "lynis-incomplete.dat"
    assert compare_lynis.main([str(BEFORE), str(inc)]) == 0
    captured = capsys.readouterr()
    assert "| **Lynis hardening index** | 58 | n/a | **n/a** |" in captured.out
    assert "different Lynis versions" in captured.out
    assert "no hardening_index" in captured.err


def test_compare_cli_json(tmp_path):
    out = tmp_path / "c.json"
    assert compare_lynis.main([str(BEFORE), str(AFTER), "--format", "json", "-o", str(out)]) == 0
    assert json.loads(out.read_text(encoding="utf-8"))["hardening_index"]["delta"] == "+9"
