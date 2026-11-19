"""scripts/check_recap.py - the idempotence gate used in CI."""

import check_recap

IDEMPOTENT = """\
TASK [SSH | Write drop-in (validated with sshd -t before it is put in place)] ***
ok: [target]

PLAY RECAP *********************************************************************
target                     : ok=57   changed=0    unreachable=0    failed=0    skipped=21   rescued=0    ignored=0
"""

NOT_IDEMPOTENT = """\
TASK [Firewall | Add allow rules (current SSH port FIRST)] *********************
\x1b[0;33mchanged: [target] => (item=22/tcp)\x1b[0m
TASK [Fail2ban | Write the sshd jail] ******************************************
ok: [target]

PLAY RECAP *********************************************************************
\x1b[0;33mtarget\x1b[0m                     : \x1b[0;32mok=57  \x1b[0m \x1b[0;33mchanged=1   \x1b[0m unreachable=0    failed=0    skipped=21   rescued=0    ignored=0
"""

FAILED = """\
PLAY RECAP *********************************************************************
target                     : ok=3    changed=0    unreachable=0    failed=1    skipped=0    rescued=0    ignored=0
"""


def _write(tmp_path, text):
    p = tmp_path / "run.log"
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_parse_recap():
    assert check_recap.parse_recap(IDEMPOTENT)["target"]["changed"] == 0
    assert check_recap.parse_recap(NOT_IDEMPOTENT)["target"]["changed"] == 1


def test_idempotent_run_passes(tmp_path, capsys):
    assert check_recap.main([_write(tmp_path, IDEMPOTENT), "--expect-changed", "0"]) == 0
    assert "OK" in capsys.readouterr().out


def test_changed_tasks_are_listed_on_failure(tmp_path, capsys):
    assert check_recap.main([_write(tmp_path, NOT_IDEMPOTENT), "--expect-changed", "0"]) == 1
    out = capsys.readouterr().out
    assert "changed=1 (expected 0)" in out
    assert "target: Firewall | Add allow rules (current SSH port FIRST)" in out


def test_failures_fail_unless_allowed(tmp_path):
    log = _write(tmp_path, FAILED)
    assert check_recap.main([log]) == 1
    assert check_recap.main([log, "--allow-failures"]) == 0


def test_missing_recap(tmp_path, capsys):
    assert check_recap.main([_write(tmp_path, "ERROR! syntax error\n")]) == 1
    assert "no PLAY RECAP" in capsys.readouterr().out
