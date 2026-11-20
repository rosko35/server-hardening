#!/usr/bin/env python3
"""Turn the interesting part of a log into GitHub Actions ``::error::`` annotations.

Job logs need a GitHub login, but annotations are readable by anyone through
the check-runs API, so a failing CI stage prints a focused excerpt this way:

    python3 ci/annotate.py --title "02-lynis-before" ci/logs/02-lynis-before.log
    some-command 2>&1 | python3 ci/annotate.py --title "systemctl --failed" -

The excerpt holds every ansible ``fatal:`` / ``failed:`` / ``ERROR!`` block
(with the TASK line it belongs to) followed by the last lines of the log. It is
split over at most ``--max-parts`` annotations of ``--part-size`` characters,
because GitHub truncates long annotations and keeps only about ten per step.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
TASK = re.compile(r"^(TASK|RUNNING HANDLER) \[")
TROUBLE = re.compile(
    r"^(fatal:|failed:|ERROR!|\[ERROR\]|An exception occurred)|FAILED!|Traceback \(most recent call last\)"
)
BLOCK_LINES = 40


def escape_data(text: str) -> str:
    """Escape a workflow-command message (``%``, CR and LF)."""
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    """Escape a workflow-command property value such as ``title``."""
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def excerpt(log: str, tail: int = 40, max_blocks: int = 4) -> str:
    """Failure blocks (with their TASK header) plus the last ``tail`` lines."""
    lines = [ANSI.sub("", line).rstrip() for line in log.splitlines()]
    blocks: list[str] = []
    covered = -1
    task_line = ""
    for i, line in enumerate(lines):
        if TASK.match(line):
            task_line = line
        if i <= covered or not TROUBLE.search(line):
            continue
        end = i + 1
        while end < len(lines) and end - i < BLOCK_LINES and not TASK.match(lines[end]):
            end += 1
        covered = end - 1
        header = [task_line] if task_line and task_line != line else []
        blocks.append("\n".join(header + lines[i:end]).strip())
        if len(blocks) >= max_blocks:
            break
    parts = []
    if blocks:
        parts.append("== failure blocks ==\n" + "\n--\n".join(blocks))
    tail_lines = lines[-tail:] if tail > 0 else []
    if tail_lines:
        parts.append(f"== last {len(tail_lines)} lines ==\n" + "\n".join(tail_lines))
    return "\n\n".join(parts) if parts else "(empty log)"


def split_parts(text: str, size: int, max_parts: int) -> list[str]:
    """Split at line boundaries into at most ``max_parts`` chunks of ~``size`` chars.

    If the text is longer, the *middle* is dropped (the start holds the failure
    blocks, the end holds the most recent output).
    """
    budget = int(size * max_parts * 0.9)  # leave room for imperfect packing
    if len(text) > budget:
        half = budget // 2 - 40
        text = text[:half] + "\n[... excerpt shortened ...]\n" + text[-half:]
    chunks: list[str] = []
    current = ""
    for line in text.splitlines(keepends=True):
        while len(line) > size:  # a single very long line
            if current:
                chunks.append(current)
                current = ""
            chunks.append(line[:size])
            line = line[size:]
        if len(current) + len(line) > size:
            chunks.append(current)
            current = ""
        current += line
    if current:
        chunks.append(current)
    return [c.rstrip("\n") for c in chunks][:max_parts] or [""]


def annotations(title: str, text: str, level: str = "error", size: int = 3500, max_parts: int = 3) -> list[str]:
    chunks = split_parts(text, size, max_parts)
    out = []
    for n, chunk in enumerate(chunks, 1):
        t = title if len(chunks) == 1 else f"{title} ({n}/{len(chunks)})"
        out.append(f"::{level} title={escape_property(t)}::{escape_data(chunk)}")
    return out


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("logfile", help="log file, or - for stdin")
    p.add_argument("--title", required=True)
    p.add_argument("--level", choices=["error", "warning", "notice"], default="error")
    p.add_argument("--tail", type=int, default=40, help="trailing lines to include")
    p.add_argument("--raw", action="store_true", help="no failure-block search, just the tail")
    p.add_argument("--part-size", type=int, default=3500)
    p.add_argument("--max-parts", type=int, default=3)
    args = p.parse_args(argv)

    if args.logfile == "-":
        log = sys.stdin.read()
    else:
        path = Path(args.logfile)
        log = path.read_text(encoding="utf-8", errors="replace") if path.exists() else f"({path} does not exist)"
    if args.raw:
        lines = [ANSI.sub("", line).rstrip() for line in log.splitlines()]
        text = "\n".join(lines[-args.tail :]) or "(no output)"
    else:
        text = excerpt(log, tail=args.tail)
    for line in annotations(args.title, text, args.level, args.part_size, args.max_parts):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
