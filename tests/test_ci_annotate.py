"""ci/annotate.py - failure excerpts as GitHub annotations (readable without login)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "ci"))

import annotate  # noqa: E402

LOG = """\
TASK [Lynis | Find an installed Lynis] *****************************************
ok: [target]

TASK [Lynis | Run the audit (read-only scan, takes 1-3 minutes)] ***************
\x1b[0;31mfatal: [target]: FAILED! => changed=false\x1b[0m
  msg: non-zero return code
  rc: 78 (100% sure)

PLAY RECAP *********************************************************************
target                     : ok=3    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
"""


def test_excerpt_contains_failed_task_and_tail():
    text = annotate.excerpt(LOG, tail=3)
    assert "TASK [Lynis | Run the audit" in text
    assert "fatal: [target]: FAILED!" in text
    assert "\x1b" not in text
    assert "Find an installed Lynis" not in text.split("== last")[0]
    assert text.rstrip().endswith("ignored=0")


def test_annotation_is_one_line_and_escaped():
    lines = annotate.annotations("02-lynis: before, run", annotate.excerpt(LOG))
    assert len(lines) == 1
    line = lines[0]
    assert line.startswith("::error title=02-lynis%3A before%2C run::")
    assert "\n" not in line and "%0A" in line
    assert "100%25 sure" in line


def test_long_text_is_split_and_capped():
    text = "\n".join(f"line {i} " + "x" * 50 for i in range(1000))
    lines = annotate.annotations("t", text, size=1000, max_parts=3)
    assert len(lines) == 3
    assert lines[0].startswith("::error title=t (1/3)::")
    assert all(len(line) < 1300 for line in lines)
    assert "line 999" in lines[-1]


def test_main_reads_missing_file(tmp_path, capsys):
    assert annotate.main(["--title", "x", str(tmp_path / "nope.log")]) == 0
    assert "does not exist" in capsys.readouterr().out
