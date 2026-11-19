"""SSH, accounts, file-mode, sysctl, rollback and findings helpers."""

import pytest
from hardening_filters import (
    authorized_keys_paths,
    backup_category,
    build_findings,
    file_mode_plan,
    findings_summary,
    login_accounts,
    md_cell,
    mode_needs_tightening,
    parse_login_defs,
    parse_passwd,
    parse_sysctl,
    rollback_actions,
    sshd_effective,
    sshd_mismatches,
    sshd_value,
    state_file_name,
    system_accounts_with_shell,
    tightened_mode,
)

SSHD_T = """\
port 22
port 2222
permitrootlogin yes
passwordauthentication yes
kbdinteractiveauthentication no
pubkeyauthentication yes
maxauthtries 6
x11forwarding yes
logingracetime 120
clientaliveinterval 0
authorizedkeysfile .ssh/authorized_keys .ssh/authorized_keys2
"""

PASSWD = """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
postgres:x:114:120:PostgreSQL:/var/lib/postgresql:/bin/bash
backupsvc:x:120:120::/var/backups:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
emre:x:1000:1000:Emre:/home/emre:/bin/bash
broken line
"""


def test_sshd_effective_keeps_repeated_keys():
    eff = sshd_effective(SSHD_T)
    assert eff["port"] == ["22", "2222"]
    assert sshd_value(eff, "PermitRootLogin") == "yes"
    assert sshd_value(eff, "missing", "dflt") == "dflt"


def test_sshd_mismatches_detects_overridden_settings():
    eff = sshd_effective(SSHD_T)
    wanted = {"PermitRootLogin": "no", "KbdInteractiveAuthentication": "no", "LoginGraceTime": "2m"}
    problems = sshd_mismatches(eff, wanted)
    assert len(problems) == 1 and problems[0].startswith("PermitRootLogin")


def test_sshd_mismatches_understands_time_units_and_booleans():
    eff = sshd_effective("logingracetime 30\nclientaliveinterval 300\nx11forwarding no\n")
    assert sshd_mismatches(eff, {"LoginGraceTime": "30s", "ClientAliveInterval": "5m", "X11Forwarding": False}) == []


def test_authorized_keys_paths_expand_tokens():
    paths = authorized_keys_paths(".ssh/authorized_keys /etc/ssh/keys/%u %h/.ssh/k2%%x", "emre", "/home/emre")
    assert paths == ["/home/emre/.ssh/authorized_keys", "/etc/ssh/keys/emre", "/home/emre/.ssh/k2%x"]
    assert authorized_keys_paths("none", "emre", "/home/emre") == []


def test_parse_passwd_and_account_classification():
    entries = parse_passwd(PASSWD)
    assert len(entries) == 7  # broken line ignored
    names = [e["name"] for e in system_accounts_with_shell(entries, 999, ["root", "sync", "postgres"])]
    assert names == ["backupsvc"]
    logins = [e["name"] for e in login_accounts(entries)]
    assert logins == ["root", "emre"]


@pytest.mark.parametrize(
    "current,desired,needs,result",
    [
        ("0644", "0600", True, "0600"),
        ("0600", "0640", False, "0600"),  # never ADDS group read
        ("0755", "0700", True, "0700"),
        ("644", "0644", False, "0644"),
        ("0777", "0640", True, "0640"),
    ],
)
def test_modes_are_only_ever_tightened(current, desired, needs, result):
    assert mode_needs_tightening(current, desired) is needs
    assert tightened_mode(current, desired) == result


def test_file_mode_plan():
    out = "/etc/crontab|644\n/etc/shadow|640\n"
    targets = [
        {"path": "/etc/crontab", "mode": "0600"},
        {"path": "/etc/shadow", "mode": "0640"},
        {"path": "/boot/grub/grub.cfg", "mode": "0600"},
    ]
    plan = {p["path"]: p for p in file_mode_plan(out, targets)}
    assert plan["/etc/crontab"]["change"] is True and plan["/etc/crontab"]["new_mode"] == "0600"
    assert plan["/etc/shadow"]["change"] is False
    assert plan["/boot/grub/grub.cfg"]["exists"] is False and plan["/boot/grub/grub.cfg"]["change"] is False


def test_state_file_name():
    assert state_file_name("/etc/cron.d") == "etc__cron.d"


def test_parse_sysctl_and_login_defs():
    assert parse_sysctl("net.ipv4.tcp_syncookies = 1\nnet.ipv4.conf.all.rp_filter = 2\n") == {
        "net.ipv4.tcp_syncookies": "1",
        "net.ipv4.conf.all.rp_filter": "2",
    }
    defs = parse_login_defs("# comment\nPASS_MAX_DAYS\t99999\n#UMASK 077\nUMASK\t\t022\n\n")
    assert defs == {"PASS_MAX_DAYS": "99999", "UMASK": "022"}


def test_backup_category_and_rollback_actions():
    root = "/var/backups/server-hardening/originals"
    files = [
        f"{root}/etc/ssh/sshd_config.d/01-server-hardening.conf.absent",
        f"{root}/etc/ufw/user.rules",
        f"{root}/etc/default/ufw",
        f"{root}/etc/login.defs",
        "/somewhere/else/file",
    ]
    assert backup_category("/etc/fail2ban/jail.d/server-hardening.local") == "fail2ban"
    actions = rollback_actions(files, root, ["all"])
    by_target = {a["target"]: a for a in actions}
    assert by_target["/etc/ssh/sshd_config.d/01-server-hardening.conf"]["action"] == "delete"
    assert by_target["/etc/ufw/user.rules"]["action"] == "restore"
    assert len(actions) == 4
    only_fw = rollback_actions(files, root, ["firewall"])
    assert {a["target"] for a in only_fw} == {"/etc/ufw/user.rules", "/etc/default/ufw"}


def test_md_cell_escapes_pipes_and_newlines():
    assert md_cell("a|b\nc") == "a\\|b<br>c"
    assert md_cell(None) == ""


def _audit(**overrides):
    base = {
        "sshd": sshd_effective(SSHD_T),
        "sshd_valid": True,
        "operator": {"user": "emre", "ip": "198.51.100.7", "has_verified_key": True},
        "ufw": {"installed": True, "active": False},
        "nft_rule_lines": 0,
        "updates": {"total": 12, "security": 3},
        "reboot_required": True,
        "unattended": {"installed": True, "enabled": False},
        "fail2ban": {"installed": False, "active": False},
        "uid0_accounts": ["root"],
        "nopasswd_sudo": [],
        "system_shell_accounts": [],
        "file_modes": [{"path": "/etc/crontab", "exists": True, "mode": "0644", "desired": "0600"}],
        "sysctl": {"net.ipv4.conf.all.accept_redirects": "1"},
        "sysctl_desired": {"net.ipv4.conf.all.accept_redirects": 0},
        "lynis_installed": False,
    }
    base.update(overrides)
    return base


def test_build_findings_covers_main_risks_and_sorts_by_severity():
    findings = build_findings(_audit())
    ids = [f["id"] for f in findings]
    for expected in (
        "ssh-root-login",
        "ssh-password-auth",
        "fw-none",
        "upd-security",
        "upd-reboot",
        "upd-unattended",
        "f2b-missing",
        "files-modes",
        "sysctl-network",
        "lynis-missing",
        "ssh-port",
    ):
        assert expected in ids, expected
    order = ["critical", "high", "medium", "low", "info"]
    sev = [order.index(f["severity"]) for f in findings]
    assert sev == sorted(sev)
    for f in findings:
        assert set(f) == {"id", "severity", "title", "detail", "why", "fix", "toggle", "risk"}


def test_build_findings_handles_stringified_booleans_from_ansible():
    findings = build_findings(_audit(reboot_required="False", lynis_installed="True", sshd_valid="True"))
    ids = {f["id"] for f in findings}
    assert "upd-reboot" not in ids
    assert "lynis-missing" not in ids
    assert "ssh-config-invalid" not in ids


def test_build_findings_flags_broken_sshd_and_extra_uid0():
    findings = build_findings(_audit(sshd_valid=False, uid0_accounts=["root", "toor"]))
    crit = {f["id"] for f in findings if f["severity"] == "critical"}
    assert {"ssh-config-invalid", "acct-uid0"} <= crit


def test_password_finding_mentions_missing_key():
    findings = build_findings(_audit(operator={"user": "emre", "has_verified_key": False}))
    pw = next(f for f in findings if f["id"] == "ssh-password-auth")
    assert "verified now: NO" in pw["fix"]


def test_would_close_mail_port_is_critical():
    plan = {"would_close": [{"spec": "587/tcp", "category": "mail", "process": "master", "service_hint": "Submission"}]}
    findings = build_findings(_audit(firewall_plan=plan))
    f = next(f for f in findings if f["id"] == "fw-would-close-587/tcp")
    assert f["severity"] == "critical"


def test_build_findings_tolerates_empty_input():
    findings = build_findings({})
    assert isinstance(findings, list)
    summary = findings_summary(findings)
    assert summary["total"] == len(findings)
