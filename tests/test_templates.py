"""Render every Jinja2 template with representative variables.

The Jinja2 environment mirrors Ansible's template module (trim_blocks) and uses
StrictUndefined, so a misspelled variable fails here instead of on a server.
"""

from pathlib import Path

import pytest
from hardening_filters import build_findings, findings_summary, firewall_plan, parse_ss, suggest_allowed_ports

ROOT = Path(__file__).resolve().parent.parent

SSH_SETTINGS = {
    "PermitRootLogin": "no",
    "PasswordAuthentication": "no",
    "KbdInteractiveAuthentication": "no",
    "PubkeyAuthentication": "yes",
    "MaxAuthTries": "4",
    "X11Forwarding": False,
    "ClientAliveInterval": 300,
}


def test_every_template_is_covered():
    """Adding a template without a rendering test should fail CI."""
    covered = {
        "roles/ssh_hardening/templates/sshd_hardening.conf.j2",
        "roles/fail2ban/templates/server-hardening.local.j2",
        "roles/firewall/templates/ufw-plan.txt.j2",
        "roles/auto_updates/templates/21server-hardening-periodic.j2",
        "roles/auto_updates/templates/52server-hardening-unattended.j2",
        "roles/sysctl_network/templates/60-server-hardening.conf.j2",
        "roles/audit/templates/report.md.j2",
    }
    found = {p.relative_to(ROOT).as_posix() for p in ROOT.glob("roles/*/templates/*.j2")}
    assert found == covered


def test_sshd_dropin(render):
    out = render(
        "roles/ssh_hardening/templates/sshd_hardening.conf.j2",
        ssh_hardening_managed=SSH_SETTINGS,
        ssh_hardening_dropin="/etc/ssh/sshd_config.d/01-server-hardening.conf",
    )
    directives = [line for line in out.splitlines() if line and not line.startswith("#")]
    assert "PasswordAuthentication no" in directives
    assert "X11Forwarding no" in directives  # Python bool rendered as sshd keyword
    assert "ClientAliveInterval 300" in directives
    assert directives == sorted(directives)
    # never manages the port, never contains Match blocks
    assert not any(d.lower().startswith(("port ", "match ")) for d in directives)
    assert len(directives) == len(SSH_SETTINGS)


def test_sshd_dropin_empty_is_valid(render):
    out = render(
        "roles/ssh_hardening/templates/sshd_hardening.conf.j2",
        ssh_hardening_managed={},
        ssh_hardening_dropin="/x",
    )
    assert all(line.startswith("#") or not line.strip() for line in out.splitlines())


def test_fail2ban_jail(render):
    out = render(
        "roles/fail2ban/templates/server-hardening.local.j2",
        fail2ban_ignoreip=["127.0.0.1/8", "::1", "198.51.100.7"],
        fail2ban_bantime="1h",
        fail2ban_findtime="10m",
        fail2ban_maxretry=5,
        common_ssh_port="22",
    )
    assert "ignoreip = 127.0.0.1/8 ::1 198.51.100.7" in out
    assert "[sshd]" in out and "enabled = true" in out
    assert "backend = systemd" in out
    assert "port    = 22" in out


@pytest.mark.parametrize("distro", ["Ubuntu", "Debian"])
@pytest.mark.parametrize("blacklist,mail", [([], ""), (["nginx", "dovecot-*"], "root@localhost")])
def test_unattended_upgrades(render, distro, blacklist, mail):
    out = render(
        "roles/auto_updates/templates/52server-hardening-unattended.j2",
        ansible_facts={"distribution": distro},
        auto_updates_package_blacklist=blacklist,
        auto_updates_mail=mail,
    )
    assert out.count("{") == out.count("}")
    assert 'Unattended-Upgrade::Automatic-Reboot "false";' in out
    assert "#clear Unattended-Upgrade::Origins-Pattern;" in out
    origins = [line.strip() for line in out.splitlines() if line.strip().startswith('"origin=')]
    assert origins and all("security" in o.lower() for o in origins)
    assert ("Package-Blacklist" in out) is bool(blacklist)
    assert ("MailReport" in out) is bool(mail)
    for line in out.splitlines():
        s = line.strip()
        if s and not s.startswith(("//", "#")) and not s.endswith(("{", "};")):
            assert s.endswith(";"), f"apt.conf statement without ';': {line!r}"


def test_periodic(render):
    out = render("roles/auto_updates/templates/21server-hardening-periodic.j2")
    assert 'APT::Periodic::Unattended-Upgrade "1";' in out


def test_sysctl(render):
    out = render(
        "roles/sysctl_network/templates/60-server-hardening.conf.j2",
        sysctl_network_desired={"net.ipv4.tcp_syncookies": 1, "net.ipv4.conf.all.accept_redirects": 0},
        harden_backup_root="/var/backups/server-hardening",
    )
    lines = [line for line in out.splitlines() if line and not line.startswith("#")]
    assert lines == ["net.ipv4.conf.all.accept_redirects = 0", "net.ipv4.tcp_syncookies = 1"]
    assert "ip_forward" not in "\n".join(lines)


def _ufw_vars(ss_output, allowed, ack=()):
    listeners = parse_ss(ss_output)
    return {
        "firewall_ufw_installed": True,
        "firewall_ufw_active": False,
        "firewall_allowed_ports": list(allowed),
        "firewall_suggested_ports": suggest_allowed_ports(listeners, 22),
        "firewall_plan_preview": firewall_plan(listeners, list(allowed), 22, list(ack), strict=False),
    }


def test_ufw_plan_lists_commands_ssh_first(render, ss_output):
    allowed = ["22/tcp", "80/tcp", "443/tcp", "25/tcp", "465/tcp", "587/tcp", "993/tcp"]
    out = render("roles/firewall/templates/ufw-plan.txt.j2", **_ufw_vars(ss_output, allowed))
    cmds = [line.split(". ", 1)[1] for line in out.splitlines() if line.strip()[:2].rstrip(".").isdigit()]
    assert cmds[0].startswith("ufw allow 22/tcp")
    assert cmds[-1] == "ufw enable"
    assert cmds.index("ufw default deny incoming") > cmds.index(
        "ufw allow 993/tcp   # server-hardening: allowed by firewall_allowed_ports"
    )


def test_ufw_plan_refuses_empty_list(render, ss_output):
    out = render("roles/firewall/templates/ufw-plan.txt.j2", **_ufw_vars(ss_output, []))
    assert "PLAN REFUSED" in out
    assert "ufw enable" not in out


def test_ufw_plan_shows_mail_ports_that_would_close(render, ss_output):
    out = render("roles/firewall/templates/ufw-plan.txt.j2", **_ufw_vars(ss_output, ["22/tcp", "80/tcp", "443/tcp"]))
    assert "587/tcp master (Submission (mail clients sending)): NOT acknowledged" in out
    assert "WARNING: !!! 25/tcp" in out


def _report_vars(ss_output, allowed):
    listeners = parse_ss(ss_output)
    plan = firewall_plan(listeners, allowed, 22, strict=False) if allowed else {}
    data = {
        "generated": "2026-11-01T10:00:00Z",
        "host": "mail",
        "hostname": "mail.example.test",
        "os": "Ubuntu 24.04",
        "kernel": "6.8.0-45-generic",
        "operator": {
            "user": "emre",
            "ip": "198.51.100.7",
            "has_verified_key": True,
            "key_files": ["/home/emre/.ssh/authorized_keys"],
        },
        "ssh_port": "22",
        "sshd": {"permitrootlogin": ["yes"], "passwordauthentication": ["yes"], "port": ["22"]},
        "sshd_valid": True,
        "sshd_error": "",
        "listeners": listeners,
        "ufw": {"installed": True, "active": False, "status": "Status: inactive"},
        "nft_rule_lines": 0,
        "firewall_plan": plan,
        "firewall_suggested_ports": suggest_allowed_ports(listeners, 22),
        "updates": {"total": 3, "security": 1, "packages": ["openssl", "libssl3", "tzdata"]},
        "reboot_required": False,
        "unattended": {"installed": True, "enabled": True},
        "fail2ban": {"installed": False, "active": False},
        "login_users": [{"name": "root", "shell": "/bin/bash"}, {"name": "emre", "shell": "/bin/bash"}],
        "uid0_accounts": ["root"],
        "sudo_groups": ["sudo:x:27:emre"],
        "nopasswd_sudo": ["emre ALL=(ALL) NOPASSWD:ALL"],
        "system_shell_accounts": [],
        "login_defs": {"PASS_MAX_DAYS": "99999"},
        "login_defs_desired": {"PASS_MAX_DAYS": "365"},
        "world_writable": [],
        "suid": ["/usr/bin/sudo", "/usr/bin/passwd"],
        "failed_units": [],
        "file_modes": [],
        "sysctl": {},
        "sysctl_desired": {},
        "lynis_installed": False,
        "toggles": {"ssh_hardening_apply": False, "firewall_apply": False},
    }
    findings = build_findings(data)
    return {"audit_data": data, "audit_findings": findings, "audit_summary": findings_summary(findings)}


@pytest.mark.parametrize("allowed", [[], ["22/tcp", "80/tcp", "443/tcp"]])
def test_audit_report(render, ss_output, allowed):
    out = render("roles/audit/templates/report.md.j2", **_report_vars(ss_output, allowed))
    assert out.startswith("# Security audit - mail")
    assert "nothing on the server was changed" in out
    header = "| Severity | What | Why it matters | How this project fixes it | Toggle | Change risk |"
    assert header in out
    rows = [line for line in out.splitlines() if line.startswith("| **")]
    assert rows, "no findings rows rendered"
    for row in rows:
        # a stray unescaped pipe would add columns
        assert row.replace("\\|", "").count("|") == 7, row
    if allowed:
        assert "would be blocked" in out and "`587/tcp`" in out
    else:
        assert "firewall_allowed_ports: [" in out
    assert "NOPASSWD" in out
