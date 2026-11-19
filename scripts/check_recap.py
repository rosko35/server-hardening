#!/usr/bin/env python3
"""Check an ansible-playbook log: idempotence (changed=0) and failures.

Used by CI after the *second* apply run:

    ansible-playbook ... | tee run2.log
    python3 scripts/check_recap.py run2.log --expect-changed 0

On failure it prints the tasks that reported "changed" so the reason is
readable directly in the CI log.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*m")
RECAP_LINE = re.compile(r"^(?P<host>\S+)\s*:\s*(?P<stats>(?:\w+=\d+\s*)+)$")
TASK_LINE = re.compile(r"^TASK \[(?P<name>.*)\]")
CHANGED_LINE = re.compile(r"^changed: \[(?P<host>[^\]]+)\]")


def parse_recap(log: str) -> dict[str, dict[str, int]]:
    """Return ``{host: {"ok": n, "changed": n, ...}}`` from the PLAY RECAP block(s).

    If the log contains several plays/runs, the last value per host wins.
    """
    hosts: dict[str, dict[str, int]] = {}
    in_recap = False
    for raw in log.splitlines():
        line = ANSI.sub("", raw).rstrip()
        if line.startswith("PLAY RECAP"):
            in_recap = True
            continue
        if in_recap:
            m = RECAP_LINE.match(line.strip())
            if m:
                stats = dict((k, int(v)) for k, v in (pair.split("=") for pair in m.group("stats").split()))
                hosts[m.group("host")] = stats
            elif line.strip() == "":
                continue
            else:
                in_recap = False
    return hosts


def changed_tasks(log: str) -> list[str]:
    """Names of tasks that printed a ``changed:`` line."""
    out: list[str] = []
    current = "?"
    for raw in log.splitlines():
        line = ANSI.sub("", raw).rstrip()
        t = TASK_LINE.match(line)
        if t:
            current = t.group("name")
            continue
        c = CHANGED_LINE.match(line)
        if c:
            out.append(f"{c.group('host')}: {current}")
    return out


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assert on an ansible-playbook PLAY RECAP.")
    parser.add_argument("logfile")
    parser.add_argument("--expect-changed", type=int, default=None, help="exact changed count per host")
    parser.add_argument("--allow-failures", action="store_true", help="do not fail on failed/unreachable")
    args = parser.parse_args(argv)

    log = Path(args.logfile).read_text(encoding="utf-8", errors="replace")
    recap = parse_recap(log)
    if not recap:
        print("FAIL: no PLAY RECAP found - did the playbook crash before finishing?")
        return 1

    problems = []
    for host, stats in recap.items():
        print(f"{host}: " + " ".join(f"{k}={v}" for k, v in stats.items()))
        if not args.allow_failures and (stats.get("failed", 0) or stats.get("unreachable", 0)):
            problems.append(f"{host}: failed={stats.get('failed', 0)} unreachable={stats.get('unreachable', 0)}")
        if args.expect_changed is not None and stats.get("changed", 0) != args.expect_changed:
            problems.append(f"{host}: changed={stats.get('changed', 0)} (expected {args.expect_changed})")

    if problems:
        print("\nFAIL:")
        for p in problems:
            print(f"  - {p}")
        tasks = changed_tasks(log)
        if args.expect_changed is not None and tasks:
            print("\nTasks that reported 'changed' (not idempotent):")
            for t in tasks:
                print(f"  * {t}")
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
