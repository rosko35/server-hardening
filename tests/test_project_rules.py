"""Project-wide safety rules, enforced as tests.

* every YAML file parses
* every toggle in group_vars/all.yml defaults to off / audit-only
* every hardening role only changes things behind its own *_apply switch
* nothing reboots, removes packages or changes the SSH port
"""

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
YAML_FILES = sorted(
    p
    for p in list(ROOT.rglob("*.yml")) + list(ROOT.rglob("*.yaml")) + [ROOT / ".yamllint", ROOT / ".ansible-lint"]
    if ".venv" not in p.parts and ".git" not in p.parts
)
HARDENING_ROLES = {
    "ssh_hardening": "ssh_hardening_apply",
    "firewall": "firewall_apply",
    "auto_updates": "auto_updates_apply",
    "fail2ban": "fail2ban_apply",
    "sysctl_network": "sysctl_network_apply",
    "accounts": "accounts_apply",
    "file_permissions": "file_permissions_apply",
}


@pytest.fixture(scope="module")
def defaults():
    return yaml.safe_load((ROOT / "group_vars" / "all.yml").read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", YAML_FILES, ids=lambda p: p.relative_to(ROOT).as_posix())
def test_yaml_is_valid(path):
    docs = list(yaml.safe_load_all(path.read_text(encoding="utf-8")))
    assert docs and docs[0] is not None


def test_every_apply_toggle_defaults_to_false(defaults):
    toggles = {k: v for k, v in defaults.items() if k.endswith("_apply")}
    assert set(toggles) == set(HARDENING_ROLES.values()) | {"lynis_apply"}
    assert all(v is False for v in toggles.values()), toggles


@pytest.mark.parametrize(
    "key,safe",
    [
        ("accounts_lock_system_shells", False),
        ("firewall_allowed_ports", []),
        ("firewall_acknowledge_closing", []),
        ("auto_updates_automatic_reboot", False),
        ("sysctl_network_strict_rp_filter", False),
        ("rollback_confirm", False),
        ("lynis_install_method", "package"),
        ("lynis_upstream_sha256", ""),
        ("harden_operator_user", ""),
        ("harden_operator_ip", ""),
    ],
)
def test_risky_switches_default_to_safe(defaults, key, safe):
    assert defaults[key] == safe


def test_every_boolean_toggle_is_off(defaults):
    on = [k for k, v in defaults.items() if v is True and k != "firewall_ipv6"]
    assert on == [], f"booleans defaulting to true: {on}"


def test_ssh_port_is_never_managed(defaults):
    assert "Port" not in defaults["ssh_hardening_settings"]
    assert not any(k.lower() == "port" for k in defaults["ssh_hardening_settings"])
    assert defaults["ssh_hardening_settings"]["PubkeyAuthentication"] == "yes"


def test_sysctl_never_touches_forwarding(defaults):
    assert not any("forward" in k for k in defaults["sysctl_network_settings"])


def test_lynis_label_and_rollback_defaults(defaults):
    assert defaults["lynis_label"] == "before"
    assert defaults["rollback_categories"] == ["all"]


@pytest.mark.parametrize("role,toggle", sorted(HARDENING_ROLES.items()))
def test_role_applies_only_behind_its_toggle(role, toggle):
    tasks = yaml.safe_load((ROOT / "roles" / role / "tasks" / "main.yml").read_text(encoding="utf-8"))
    includes = [t for t in tasks if "ansible.builtin.include_tasks" in t]
    assert len(includes) == 1, "exactly one include of apply.yml expected"
    inc = includes[0]
    assert inc["ansible.builtin.include_tasks"]["file"] == "apply.yml"
    assert inc["when"] == f"{toggle} | bool"
    # Nothing in main.yml other than the guarded include may change the system:
    for task in _walk(tasks):
        for module in (
            "ansible.builtin.template",
            "ansible.builtin.copy",
            "ansible.builtin.apt",
            "ansible.builtin.lineinfile",
            "community.general.ufw",
            "ansible.builtin.user",
            "ansible.builtin.file",
            "ansible.builtin.systemd_service",
        ):
            assert module not in task, f"{module} used outside apply.yml in {role}: {task.get('name')}"


def test_read_only_commands_in_preflights_are_marked_unchanged():
    """Every command/shell outside apply/restore/handlers must say changed_when: false."""
    for path in ROOT.glob("roles/*/tasks/*.yml"):
        if path.name in {"apply.yml", "restore.yml", "install.yml"}:
            continue
        tasks = yaml.safe_load(path.read_text(encoding="utf-8"))
        for task in _walk(tasks):
            if "ansible.builtin.command" in task or "ansible.builtin.shell" in task:
                assert task.get("changed_when") is False, f"{path.name}: {task.get('name')}"


def _walk(tasks):
    for t in tasks or []:
        yield t
        for key in ("block", "rescue", "always"):
            yield from _walk(t.get(key))


FORBIDDEN = [
    (r"ansible\.builtin\.reboot|(command|shell|argv):.*\b(reboot|shutdown|init 6)\b", "reboots"),
    (r"state:\s*absent\s*\n(?:.*\n){0,3}?.*(apt|package)", "package removal"),
    (r"ansible\.builtin\.(apt|package):(?:\n.*){0,4}state:\s*absent", "package removal"),
    (r"ansible\.posix\.sysctl", "direct sysctl module (bypasses backup)"),
    (r"^\s*Port\s+\d+", "SSH port change"),
]


@pytest.mark.parametrize("pattern,what", FORBIDDEN, ids=[w for _, w in FORBIDDEN])
def test_no_forbidden_operations(pattern, what):
    for path in list(ROOT.glob("roles/**/*.yml")) + list(ROOT.glob("roles/**/*.j2")) + list(ROOT.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert not re.search(pattern, text, re.MULTILINE), f"{what} found in {path.relative_to(ROOT)}"


def test_every_role_has_meta():
    for role in (ROOT / "roles").iterdir():
        meta = yaml.safe_load((role / "meta" / "main.yml").read_text(encoding="utf-8"))
        assert meta["galaxy_info"]["license"] == "MIT"


def test_real_inventory_is_ignored():
    gi = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for entry in ("inventory/hosts.yml", ".venv/", "reports/", "backups/", "*.retry"):
        assert entry in gi
