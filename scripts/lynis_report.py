#!/usr/bin/env python3
"""Parse a Lynis ``lynis-report.dat`` file into JSON or Markdown.

Usage:
    python3 scripts/lynis_report.py reports/mail/lynis-before.dat
    python3 scripts/lynis_report.py reports/mail/lynis-before.dat --format json -o before.json

Standard library only, so it runs on the server, in WSL, on Windows or in CI.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

SCALAR_KEYS = {
    "hardening_index": "hardening_index",
    "lynis_version": "lynis_version",
    "hostname": "hostname",
    "os_fullname": "os",
    "os_name": "os_name",
    "os_version": "os_version",
    "lynis_tests_done": "tests_done",
    "report_datetime_start": "started",
    "report_datetime_end": "finished",
}


def _parse_item(value: str) -> dict:
    """``TEST-ID|message|details|solution|`` -> dict ("-" means empty)."""
    parts = [p.strip() for p in value.split("|")]
    parts += [""] * (4 - len(parts))

    def clean(v: str) -> str:
        return "" if v in {"-", "", "text:-"} else v

    return {
        "test_id": clean(parts[0]),
        "message": clean(parts[1]),
        "details": clean(parts[2]),
        "solution": clean(parts[3]),
    }


def parse_report(text: str) -> dict:
    """Parse the content of a lynis-report.dat file."""
    data: dict = {
        "hardening_index": None,
        "lynis_version": "",
        "hostname": "",
        "os": "",
        "os_name": "",
        "os_version": "",
        "tests_done": None,
        "started": "",
        "finished": "",
        "warnings": [],
        "suggestions": [],
    }
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        if key == "warning[]":
            data["warnings"].append(_parse_item(value))
        elif key == "suggestion[]":
            data["suggestions"].append(_parse_item(value))
        elif key in SCALAR_KEYS:
            data[SCALAR_KEYS[key]] = value.strip()

    for int_key in ("hardening_index", "tests_done"):
        val = data[int_key]
        data[int_key] = int(val) if isinstance(val, str) and val.isdigit() else None
    data["warning_count"] = len(data["warnings"])
    data["suggestion_count"] = len(data["suggestions"])
    return data


def load_report(path: str | Path) -> dict:
    return parse_report(Path(path).read_text(encoding="utf-8", errors="replace"))


def _cell(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def to_markdown(report: dict, title: str = "Lynis report") -> str:
    hi = report["hardening_index"]
    lines = [
        f"## {title}",
        "",
        f"- Host: `{report['hostname'] or '?'}` - {report['os'] or '?'}",
        f"- Lynis version: {report['lynis_version'] or '?'}",
        f"- Run: {report['started'] or '?'}",
        f"- **Hardening index: {hi if hi is not None else 'n/a'} / 100**",
        f"- Tests performed: {report['tests_done'] if report['tests_done'] is not None else 'n/a'}",
        f"- Warnings: {report['warning_count']} - Suggestions: {report['suggestion_count']}",
        "",
    ]
    if report["warnings"]:
        lines += ["### Warnings", "", "| Test | Message | Details |", "|---|---|---|"]
        lines += [
            f"| {_cell(w['test_id'])} | {_cell(w['message'])} | {_cell(w['details'])} |" for w in report["warnings"]
        ]
        lines.append("")
    if report["suggestions"]:
        lines += ["### Suggestions", "", "| Test | Suggestion | Details |", "|---|---|---|"]
        lines += [
            f"| {_cell(s['test_id'])} | {_cell(s['message'])} | {_cell(s['details'])} |" for s in report["suggestions"]
        ]
        lines.append("")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Summarise a Lynis lynis-report.dat file.")
    parser.add_argument("report", help="path to lynis-report.dat")
    parser.add_argument("--format", choices=["md", "json"], default="md")
    parser.add_argument("-o", "--output", help="write to this file instead of stdout")
    args = parser.parse_args(argv)

    path = Path(args.report)
    if not path.is_file():
        print(f"error: {path} not found", file=sys.stderr)
        return 2
    report = load_report(path)
    if report["hardening_index"] is None:
        print(f"warning: no hardening_index in {path} (incomplete Lynis run?)", file=sys.stderr)

    out = json.dumps(report, indent=2) + "\n" if args.format == "json" else to_markdown(report) + "\n"
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
    else:
        sys.stdout.write(out)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
