"""Jinja2 filters used by the server-hardening roles.

Everything that makes a *decision* (what is listening, what a firewall rule set
would close, which findings to report, whether a file mode is too open) lives
here in plain Python instead of in YAML, so it can be unit-tested with pytest on
any machine - including one where Ansible itself cannot run.

The module deliberately has no hard dependency on Ansible: when Ansible is not
importable (unit tests) a local exception class is used instead.
"""

from __future__ import annotations

import re

try:  # pragma: no cover - exercised only when running under Ansible
    from ansible.errors import AnsibleFilterError
except ImportError:  # pragma: no cover - exercised in unit tests

    class AnsibleFilterError(Exception):
        """Stand-in used when Ansible is not installed."""


MAIL_PORTS = {
    25: "SMTP (incoming mail)",
    465: "SMTPS (mail submission over TLS)",
    587: "Submission (mail clients sending)",
    110: "POP3",
    143: "IMAP",
    993: "IMAPS",
    995: "POP3S",
    4190: "ManageSieve",
}
WEB_PORTS = {80: "HTTP", 443: "HTTPS"}

# UDP sockets that are *clients* (they receive replies, they are not services),
# ufw's default before.rules already allow their traffic.
UDP_CLIENT_PORTS = {68: "DHCP client", 546: "DHCPv6 client", 323: "chrony (NTP) control"}

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

NO_LOGIN_SHELLS = {
    "/usr/sbin/nologin",
    "/sbin/nologin",
    "/bin/false",
    "/usr/bin/false",
    "",
}

_PORT_SPEC = re.compile(r"^(?P<start>\d{1,5})(?::(?P<end>\d{1,5}))?(?:/(?P<proto>tcp|udp))?$")
_PROCESS = re.compile(r'users:\(\("(?P<name>[^"]+)"')


# --------------------------------------------------------------------------- #
# Listening sockets
# --------------------------------------------------------------------------- #
def _split_host_port(local: str) -> tuple[str, int] | None:
    if ":" not in local:
        return None
    host, _, port = local.rpartition(":")
    if not port.isdigit():
        return None
    host = host.split("%", 1)[0]  # strip interface suffix: 127.0.0.53%lo
    host = host.strip("[]")
    return host, int(port)


def _is_loopback(host: str) -> bool:
    return host.startswith("127.") or host in {"::1", "localhost"}


def port_category(port: int) -> str:
    if port in MAIL_PORTS:
        return "mail"
    if port in WEB_PORTS:
        return "web"
    return "other"


def parse_ss(output: str) -> list[dict]:
    """Parse ``ss -H -tulpn`` output into a de-duplicated list of listeners.

    Each item: ``{proto, port, addresses, process, public, category}``.
    ``public`` is True when at least one bound address is not loopback.
    """
    merged: dict[tuple[str, int], dict] = {}
    for raw in (output or "").splitlines():
        parts = raw.split()
        if len(parts) < 5:
            continue
        netid = parts[0].lower()
        if netid not in {"tcp", "udp"}:
            continue
        state = parts[1].upper()
        if netid == "tcp" and state != "LISTEN":
            continue
        hp = _split_host_port(parts[4])
        if hp is None:
            continue
        host, port = hp
        m = _PROCESS.search(raw)
        process = m.group("name") if m else "unknown"
        key = (netid, port)
        item = merged.setdefault(
            key,
            {
                "proto": netid,
                "port": port,
                "addresses": [],
                "process": process,
                "public": False,
                "category": port_category(port),
            },
        )
        if host not in item["addresses"]:
            item["addresses"].append(host)
        if not _is_loopback(host):
            item["public"] = True
        if item["process"] == "unknown" and process != "unknown":
            item["process"] = process
    return sorted(merged.values(), key=lambda i: (i["port"], i["proto"]))


def public_listeners(listeners: list[dict]) -> list[dict]:
    """Public listeners that a firewall would affect (UDP client sockets excluded)."""
    out = []
    for item in listeners or []:
        if not item.get("public"):
            continue
        if item.get("proto") == "udp" and item.get("port") in UDP_CLIENT_PORTS:
            continue
        out.append(item)
    return out


# --------------------------------------------------------------------------- #
# Firewall plan
# --------------------------------------------------------------------------- #
def normalize_port_spec(spec) -> dict:
    """Turn ``22``, ``"443/tcp"`` or ``"60000:61000/udp"`` into a rule dict.

    A bare port (no protocol) means TCP: every mail and web service here is TCP,
    and opening UDP "just in case" is exactly what we do not want.
    """
    text = str(spec).strip().lower()
    m = _PORT_SPEC.match(text)
    if not m:
        raise AnsibleFilterError(f"Invalid port '{spec}'. Use forms like 22, '443/tcp', '53/udp' or '60000:61000/udp'.")
    start = int(m.group("start"))
    end = int(m.group("end")) if m.group("end") else start
    proto = m.group("proto") or "tcp"
    if not (1 <= start <= 65535 and 1 <= end <= 65535 and start <= end):
        raise AnsibleFilterError(f"Port out of range in '{spec}' (valid: 1-65535).")
    port = str(start) if start == end else f"{start}:{end}"
    return {"port": port, "proto": proto, "start": start, "end": end}


def _covers(rule: dict, port: int, proto: str) -> bool:
    return rule["proto"] == proto and rule["start"] <= port <= rule["end"]


def firewall_plan(listeners, allowed_ports, ssh_port, acknowledged_closing=None, strict=True) -> dict:
    """Compute the ufw rule set and its consequences.

    * ``allowed_ports`` must be explicitly provided and non-empty, otherwise the
      plan is refused (an empty list + "default deny" = locked out).
    * The current SSH port is always the first rule, even if the operator forgot it.
    * Public listeners that would be blocked are reported in ``would_close``;
      the ones not listed in ``acknowledged_closing`` are ``unacknowledged`` and,
      in strict mode, make the plan fail.
    """
    errors: list[str] = []
    warnings: list[str] = []
    rules: list[dict] = []

    try:
        ssh_port_int = int(ssh_port)
    except (TypeError, ValueError):
        ssh_port_int = 0
    if not 1 <= ssh_port_int <= 65535:
        errors.append(f"Could not determine the current SSH port (got {ssh_port!r}); refusing to plan a firewall.")

    allowed_list = list(allowed_ports or [])
    if not allowed_list:
        errors.append(
            "firewall_allowed_ports is empty. Refusing to build a firewall with an empty allow list - "
            "list every port that must stay reachable (e.g. ['22/tcp', '80/tcp', '443/tcp'])."
        )

    if ssh_port_int:
        rules.append(
            {
                "port": str(ssh_port_int),
                "proto": "tcp",
                "start": ssh_port_int,
                "end": ssh_port_int,
                "comment": "SSH (current session) - always allowed first",
            }
        )

    for spec in allowed_list:
        try:
            rule = normalize_port_spec(spec)
        except AnsibleFilterError as exc:
            errors.append(str(exc))
            continue
        if any(r["port"] == rule["port"] and r["proto"] == rule["proto"] for r in rules):
            continue
        rule["comment"] = "server-hardening: allowed by firewall_allowed_ports"
        rules.append(rule)

    if ssh_port_int and allowed_list:
        listed = [normalize_port_spec(s) for s in allowed_list if _PORT_SPEC.match(str(s).strip().lower())]
        if not any(_covers(r, ssh_port_int, "tcp") for r in listed):
            warnings.append(
                f"SSH port {ssh_port_int}/tcp was not in firewall_allowed_ports; it is added automatically."
            )

    ack = set()
    for spec in acknowledged_closing or []:
        try:
            r = normalize_port_spec(spec)
            ack.add((r["start"], r["proto"]))
        except AnsibleFilterError as exc:
            errors.append(f"firewall_acknowledge_closing: {exc}")

    would_close = []
    for item in public_listeners(listeners):
        if any(_covers(r, item["port"], item["proto"]) for r in rules):
            continue
        entry = dict(item)
        entry["spec"] = f"{item['port']}/{item['proto']}"
        entry["service_hint"] = MAIL_PORTS.get(item["port"]) or WEB_PORTS.get(item["port"]) or ""
        entry["acknowledged"] = (item["port"], item["proto"]) in ack
        would_close.append(entry)
        if entry["category"] in {"mail", "web"}:
            warnings.append(
                f"!!! {entry['spec']} ({entry['service_hint']}, process '{item['process']}') is listening "
                f"publicly and would be BLOCKED. Your {entry['category']} service would stop working."
            )
        else:
            warnings.append(
                f"{entry['spec']} (process '{item['process']}') is listening publicly and would be blocked."
            )

    unacknowledged = [w for w in would_close if not w["acknowledged"]]

    listening_ports = {(i["port"], i["proto"]) for i in listeners or []}
    for rule in rules[1:]:
        if rule["start"] == rule["end"] and (rule["start"], rule["proto"]) not in listening_ports:
            warnings.append(f"{rule['port']}/{rule['proto']} is allowed but nothing listens on it (typo?).")

    plan = {
        "ok": not errors and not unacknowledged,
        "rules": [{"port": r["port"], "proto": r["proto"], "comment": r["comment"]} for r in rules],
        "would_close": would_close,
        "unacknowledged": unacknowledged,
        "warnings": warnings,
        "errors": errors,
    }

    if strict:
        if errors:
            raise AnsibleFilterError("Firewall plan refused:\n- " + "\n- ".join(errors))
        if unacknowledged:
            specs = ", ".join(u["spec"] for u in unacknowledged)
            raise AnsibleFilterError(
                "Firewall plan refused: these publicly listening ports would be blocked: "
                f"{specs}. Add them to firewall_allowed_ports, or - only if you really want them "
                "closed - list them in firewall_acknowledge_closing."
            )
    return plan


# --------------------------------------------------------------------------- #
# SSH
# --------------------------------------------------------------------------- #
def sshd_effective(text: str) -> dict:
    """Parse ``sshd -T`` output into ``{keyword: [values, ...]}`` (lower-case keys)."""
    result: dict[str, list[str]] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition(" ")
        result.setdefault(key.lower(), []).append(value.strip())
    return result


def sshd_value(effective: dict, key: str, default: str = "") -> str:
    values = (effective or {}).get(key.lower()) or []
    return values[0] if values else default


def authorized_keys_paths(authorizedkeysfile: str, user: str, home: str) -> list[str]:
    """Expand sshd's AuthorizedKeysFile tokens (%h, %u, %%) for one user."""
    paths = []
    for token in (authorizedkeysfile or ".ssh/authorized_keys").split():
        if token.lower() == "none":
            continue
        expanded = token.replace("%%", "\0").replace("%h", home).replace("%u", user).replace("\0", "%")
        if not expanded.startswith("/"):
            expanded = home.rstrip("/") + "/" + expanded
        if expanded not in paths:
            paths.append(expanded)
    return paths


_TIME_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}
_TIME_KEYS = {"logingracetime", "clientaliveinterval"}
_BOOL_WORDS = {True: "yes", False: "no"}


def _sshd_seconds(value: str) -> str:
    """sshd -T prints time values in seconds; accept '30', '30s', '1m', '1h30m'."""
    total, number = 0, ""
    for ch in str(value).strip().lower():
        if ch.isdigit():
            number += ch
        elif ch in _TIME_UNITS and number:
            total += int(number) * _TIME_UNITS[ch]
            number = ""
        else:
            return str(value)
    if number:
        total += int(number)
    return str(total)


def sshd_mismatches(effective: dict, desired: dict) -> list[str]:
    """Settings from ``desired`` that ``sshd -T`` does not report as in effect."""
    problems = []
    for key, want in (desired or {}).items():
        want_s = _BOOL_WORDS.get(want, str(want)) if isinstance(want, bool) else str(want)
        got = sshd_value(effective, key, "<unset>")
        if key.lower() in _TIME_KEYS:
            want_cmp, got_cmp = _sshd_seconds(want_s), _sshd_seconds(got)
        else:
            want_cmp, got_cmp = want_s.lower(), got.lower()
        if want_cmp != got_cmp:
            problems.append(f"{key}: wanted {want_s}, effective {got}")
    return problems


# --------------------------------------------------------------------------- #
# Accounts
# --------------------------------------------------------------------------- #
def parse_passwd(text: str) -> list[dict]:
    entries = []
    for line in (text or "").splitlines():
        parts = line.strip().split(":")
        if len(parts) != 7 or not parts[2].isdigit():
            continue
        entries.append(
            {
                "name": parts[0],
                "uid": int(parts[2]),
                "gid": int(parts[3]) if parts[3].isdigit() else -1,
                "home": parts[5],
                "shell": parts[6],
            }
        )
    return entries


def has_login_shell(entry: dict) -> bool:
    return entry.get("shell", "") not in NO_LOGIN_SHELLS


def system_accounts_with_shell(entries, sys_uid_max=999, exclude=None) -> list[dict]:
    """System accounts (0 < uid <= SYS_UID_MAX) that still have an interactive shell."""
    excluded = set(exclude or [])
    return [
        e
        for e in entries or []
        if 0 < e["uid"] <= int(sys_uid_max) and has_login_shell(e) and e["name"] not in excluded
    ]


def login_accounts(entries, uid_min=1000) -> list[dict]:
    return [
        e
        for e in entries or []
        if (e["uid"] == 0 or e["uid"] >= int(uid_min)) and e["uid"] != 65534 and has_login_shell(e)
    ]


# --------------------------------------------------------------------------- #
# File modes - only ever remove permission bits, never add them
# --------------------------------------------------------------------------- #
def _mode_int(mode) -> int:
    return int(str(mode).strip(), 8)


def mode_needs_tightening(current, desired) -> bool:
    return bool(_mode_int(current) & ~_mode_int(desired) & 0o7777)


def tightened_mode(current, desired) -> str:
    """Intersection of current and desired: removes extra bits, never grants new ones."""
    return "0%03o" % (_mode_int(current) & _mode_int(desired) & 0o7777)


def file_mode_plan(stat_output: str, targets) -> list[dict]:
    """Combine ``stat -c '%n|%a'`` output with the wanted modes.

    Returns one dict per target: path, exists, mode, desired, new_mode, change.
    ``new_mode`` only ever removes bits (see ``tightened_mode``).
    """
    current = {}
    for line in (stat_output or "").splitlines():
        path, sep, mode = line.strip().rpartition("|")
        if sep and mode.isdigit():
            current[path] = mode.zfill(4)
    plan = []
    for t in targets or []:
        path, desired = t["path"], str(t["mode"]).zfill(4)
        mode = current.get(path)
        item = {"path": path, "exists": mode is not None, "mode": mode or "", "desired": desired}
        if mode is not None:
            item["new_mode"] = tightened_mode(mode, desired)
            item["change"] = mode_needs_tightening(mode, desired)
        else:
            item["new_mode"], item["change"] = "", False
        plan.append(item)
    return plan


def state_file_name(path: str) -> str:
    """Flat, reversible-enough file name for per-path state files."""
    return path.strip("/").replace("/", "__") or "root"


# --------------------------------------------------------------------------- #
# sysctl / login.defs parsing
# --------------------------------------------------------------------------- #
def parse_sysctl(output: str) -> dict:
    """``sysctl a.b c.d`` output (``key = value``) -> dict of strings."""
    result = {}
    for line in (output or "").splitlines():
        key, sep, value = line.partition("=")
        if sep:
            result[key.strip()] = " ".join(value.split())
    return result


def parse_login_defs(text: str) -> dict:
    """Active (uncommented) ``KEY value`` pairs from /etc/login.defs."""
    result = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            result[parts[0]] = parts[1].strip()
    return result


# --------------------------------------------------------------------------- #
# Backups / rollback
# --------------------------------------------------------------------------- #
_BACKUP_CATEGORIES = (
    ("/etc/ssh/", "ssh"),
    ("/etc/ufw/", "firewall"),
    ("/etc/default/ufw", "firewall"),
    ("/etc/apt/apt.conf.d/", "auto_updates"),
    ("/etc/fail2ban/", "fail2ban"),
    ("/etc/sysctl.d/", "sysctl"),
    ("/etc/login.defs", "accounts"),
)


def backup_category(path: str) -> str:
    """Which hardening category a backed-up path belongs to (for partial rollback)."""
    target = path[: -len(".absent")] if path.endswith(".absent") else path
    for prefix, category in _BACKUP_CATEGORIES:
        if target == prefix or target.startswith(prefix):
            return category
    return "other"


def rollback_actions(backup_files, originals_root: str, categories=None) -> list[dict]:
    """Turn the list of files under ``originals/`` into restore/delete actions."""
    wanted = set(categories or ["all"])
    root = originals_root.rstrip("/")
    actions = []
    for f in sorted(backup_files or []):
        if not f.startswith(root + "/"):
            continue
        rel = f[len(root) :]
        absent = rel.endswith(".absent")
        target = rel[: -len(".absent")] if absent else rel
        category = backup_category(target)
        if "all" not in wanted and category not in wanted:
            continue
        actions.append(
            {"backup": f, "target": target, "action": "delete" if absent else "restore", "category": category}
        )
    return actions


def suggest_allowed_ports(listeners, ssh_port) -> list[str]:
    """A starting point for firewall_allowed_ports: SSH + everything listening publicly."""
    specs = [f"{int(ssh_port)}/tcp"] if str(ssh_port).isdigit() else []
    for item in public_listeners(listeners):
        spec = f"{item['port']}/{item['proto']}"
        if spec not in specs:
            specs.append(spec)
    return specs


# --------------------------------------------------------------------------- #
# Reporting helpers
# --------------------------------------------------------------------------- #
def md_cell(value) -> str:
    """Make a value safe for a Markdown table cell."""
    text = str(value if value is not None else "")
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r", "").replace("\n", "<br>")


def _truthy(value) -> bool:
    """Booleans may arrive as strings from Ansible templating ("True", "false", "yes")."""
    if isinstance(value, str):
        return value.strip().lower() in {"true", "yes", "1", "on"}
    return bool(value)


def _f(fid, severity, title, detail, why, fix, toggle, risk="low"):
    return {
        "id": fid,
        "severity": severity,
        "title": title,
        "detail": detail,
        "why": why,
        "fix": fix,
        "toggle": toggle,
        "risk": risk,
    }


def build_findings(audit: dict) -> list[dict]:
    """Turn raw audit data into a sorted list of findings.

    ``audit`` is the dict assembled by the ``audit`` role (see its tasks). Missing
    keys are tolerated so a partial audit still produces a useful report.
    """
    a = audit or {}
    findings: list[dict] = []
    sshd = a.get("sshd") or {}
    operator = a.get("operator") or {}

    # ---- SSH -----------------------------------------------------------------
    if "sshd_valid" in a and not _truthy(a.get("sshd_valid")):
        findings.append(
            _f(
                "ssh-config-invalid",
                "critical",
                "sshd configuration does not validate (sshd -t failed)",
                a.get("sshd_error", ""),
                "A broken sshd config means the next SSH restart (or reboot) may leave you locked out.",
                "Fix manually before anything else; this project refuses to touch SSH while sshd -t fails.",
                "(manual)",
                "n/a",
            )
        )
    if sshd:
        root_login = sshd_value(sshd, "permitrootlogin")
        if root_login == "yes":
            findings.append(
                _f(
                    "ssh-root-login",
                    "high",
                    "Root can log in over SSH with any method",
                    f"PermitRootLogin {root_login}",
                    "Root is the first account every bot tries; a direct root login also hides who did what.",
                    "Set PermitRootLogin no in a validated sshd drop-in (you keep logging in as your sudo user).",
                    "ssh_hardening_apply",
                    "medium",
                )
            )
        elif root_login in {"prohibit-password", "without-password"}:
            findings.append(
                _f(
                    "ssh-root-login",
                    "medium",
                    "Root can log in over SSH with a key",
                    f"PermitRootLogin {root_login}",
                    "Anyone holding a root key gets full control without going through sudo.",
                    "Set PermitRootLogin no (skipped automatically if you are connected as root).",
                    "ssh_hardening_apply",
                    "medium",
                )
            )
        if sshd_value(sshd, "passwordauthentication") == "yes":
            has_key = _truthy(operator.get("has_verified_key"))
            findings.append(
                _f(
                    "ssh-password-auth",
                    "high",
                    "SSH accepts passwords",
                    "PasswordAuthentication yes",
                    "Password logins can be brute-forced; keys cannot be guessed.",
                    "Set PasswordAuthentication no - only after the playbook verifies an authorized key "
                    f"for '{operator.get('user', '?')}' (verified now: {'yes' if has_key else 'NO'}).",
                    "ssh_hardening_apply",
                    "high",
                )
            )
        if sshd_value(sshd, "kbdinteractiveauthentication") == "yes":
            findings.append(
                _f(
                    "ssh-kbd-interactive",
                    "medium",
                    "Keyboard-interactive auth is enabled",
                    "KbdInteractiveAuthentication yes",
                    "It is another way to type a password even when PasswordAuthentication is off.",
                    "Set KbdInteractiveAuthentication no.",
                    "ssh_hardening_apply",
                    "high",
                )
            )
        try:
            tries = int(sshd_value(sshd, "maxauthtries", "6"))
        except ValueError:
            tries = 6
        if tries > 4:
            findings.append(
                _f(
                    "ssh-max-auth-tries",
                    "low",
                    "Many authentication attempts per connection",
                    f"MaxAuthTries {tries}",
                    "Fewer tries per connection slows down guessing.",
                    "Set MaxAuthTries 4.",
                    "ssh_hardening_apply",
                    "low",
                )
            )
        if sshd_value(sshd, "x11forwarding") == "yes":
            findings.append(
                _f(
                    "ssh-x11",
                    "low",
                    "X11 forwarding enabled",
                    "X11Forwarding yes",
                    "A server has no use for graphical forwarding; it only adds attack surface.",
                    "Set X11Forwarding no.",
                    "ssh_hardening_apply",
                    "low",
                )
            )
        if sshd_value(sshd, "allowagentforwarding") == "yes":
            findings.append(
                _f(
                    "ssh-agent-forwarding",
                    "low",
                    "SSH agent forwarding allowed",
                    "AllowAgentForwarding yes",
                    "If the server is compromised, a forwarded agent can be used to reach your other machines.",
                    "Set AllowAgentForwarding no.",
                    "ssh_hardening_apply",
                    "low",
                )
            )
        if sshd_value(sshd, "clientaliveinterval", "0") == "0":
            findings.append(
                _f(
                    "ssh-idle",
                    "low",
                    "Idle SSH sessions are never checked",
                    "ClientAliveInterval 0",
                    "Dead sessions linger forever; keepalives clean them up.",
                    "Set ClientAliveInterval 300 / ClientAliveCountMax 3.",
                    "ssh_hardening_apply",
                    "low",
                )
            )
        port = sshd_value(sshd, "port", "22")
        findings.append(
            _f(
                "ssh-port",
                "info",
                f"SSH listens on port {port}",
                f"Port {port}",
                "Moving SSH only reduces log noise; it is not a security boundary and is the #1 cause of lock-outs.",
                "Deliberately NOT changed by this project.",
                "(none)",
                "n/a",
            )
        )

    # ---- Firewall ------------------------------------------------------------
    ufw = a.get("ufw") or {}
    if not _truthy(ufw.get("active")) and int(a.get("nft_rule_lines", 0) or 0) < 5:
        findings.append(
            _f(
                "fw-none",
                "high",
                "No active host firewall",
                f"ufw installed={ufw.get('installed', False)}, active=False",
                "Every service that listens publicly - even by accident - is reachable from the internet.",
                "Enable ufw with an allow list built from what is actually listening (SSH port always first).",
                "firewall_apply",
                "high",
            )
        )
    plan = a.get("firewall_plan") or {}
    for item in plan.get("would_close", []):
        sev = "critical" if item.get("category") in {"mail", "web"} else "high"
        findings.append(
            _f(
                f"fw-would-close-{item['spec']}",
                sev,
                f"Proposed firewall would block {item['spec']}",
                f"process '{item.get('process')}' listens publicly ({item.get('service_hint') or 'unknown service'})",
                "Enabling the firewall as configured would cut this service off.",
                "Add the port to firewall_allowed_ports (or acknowledge it in firewall_acknowledge_closing).",
                "firewall_allowed_ports",
                "high",
            )
        )

    # ---- Updates -------------------------------------------------------------
    upd = a.get("updates") or {}
    if int(upd.get("security", 0) or 0) > 0:
        findings.append(
            _f(
                "upd-security",
                "high",
                f"{upd['security']} security update(s) pending",
                f"{upd.get('total', 0)} total pending",
                "Known, published vulnerabilities stay exploitable until patched.",
                "Install them (sudo apt update && sudo apt upgrade); auto_updates keeps them coming.",
                "auto_updates_apply",
                "low",
            )
        )
    elif int(upd.get("total", 0) or 0) > 0:
        findings.append(
            _f(
                "upd-pending",
                "low",
                f"{upd['total']} non-security update(s) pending",
                "",
                "Not urgent, but keep the system current.",
                "sudo apt update && sudo apt upgrade (manual).",
                "(manual)",
                "low",
            )
        )
    if _truthy(a.get("reboot_required")):
        findings.append(
            _f(
                "upd-reboot",
                "medium",
                "A reboot is required",
                "/var/run/reboot-required exists",
                "A patched kernel or library is not active until the machine restarts.",
                "Reboot yourself in a quiet moment. This project never reboots.",
                "(manual)",
                "medium",
            )
        )
    uu = a.get("unattended") or {}
    if not _truthy(uu.get("installed")) or not _truthy(uu.get("enabled")):
        findings.append(
            _f(
                "upd-unattended",
                "medium",
                "Automatic security updates are not active",
                f"installed={uu.get('installed', False)}, enabled={uu.get('enabled', False)}",
                "Most break-ins use bugs that were patched weeks earlier.",
                "Install unattended-upgrades limited to the security pocket, automatic reboot OFF.",
                "auto_updates_apply",
                "low",
            )
        )

    # ---- fail2ban ------------------------------------------------------------
    f2b = a.get("fail2ban") or {}
    if not _truthy(f2b.get("installed")) or not _truthy(f2b.get("active")):
        findings.append(
            _f(
                "f2b-missing",
                "medium",
                "No brute-force protection (fail2ban)",
                f"installed={f2b.get('installed', False)}, active={f2b.get('active', False)}",
                "Bots try thousands of passwords per day; fail2ban bans them after a few failures.",
                "Install fail2ban with an sshd jail; your current IP is put in ignoreip so you cannot ban yourself.",
                "fail2ban_apply",
                "low",
            )
        )

    # ---- Accounts ------------------------------------------------------------
    uid0 = [u for u in a.get("uid0_accounts", []) if u != "root"]
    if uid0:
        findings.append(
            _f(
                "acct-uid0",
                "critical",
                "Accounts other than root have UID 0",
                ", ".join(uid0),
                "UID 0 is root; an extra one is a classic backdoor.",
                "Investigate manually.",
                "(manual)",
                "n/a",
            )
        )
    if a.get("nopasswd_sudo"):
        findings.append(
            _f(
                "acct-nopasswd",
                "medium",
                "sudo without password is configured",
                "; ".join(a["nopasswd_sudo"][:5]),
                "Anyone who gets your SSH key also gets root instantly.",
                "Review manually (cloud images add this). Not changed automatically: it could lock you out of sudo.",
                "(manual)",
                "high",
            )
        )
    sys_shells = a.get("system_shell_accounts") or []
    if sys_shells:
        findings.append(
            _f(
                "acct-system-shells",
                "low",
                f"{len(sys_shells)} system account(s) have a login shell",
                ", ".join(f"{e['name']}({e['shell']})" for e in sys_shells[:10]),
                "Service accounts never need to log in; a shell makes a hijacked service more useful to an attacker.",
                "Set their shell to /usr/sbin/nologin (previous shells are saved for rollback).",
                "accounts_lock_system_shells",
                "medium",
            )
        )
    ld = a.get("login_defs") or {}
    want_ld = a.get("login_defs_desired") or {}
    diff_ld = {k: (ld.get(k, "unset"), v) for k, v in want_ld.items() if str(v) != "" and str(ld.get(k, "")) != str(v)}
    if diff_ld:
        findings.append(
            _f(
                "acct-login-defs",
                "low",
                "Password ageing / umask defaults differ from policy",
                ", ".join(f"{k}: {c} -> {w}" for k, (c, w) in sorted(diff_ld.items())),
                "Applies to NEW accounts; sensible defaults avoid weak forgotten accounts.",
                "Update /etc/login.defs (backup kept).",
                "accounts_apply",
                "low",
            )
        )

    # ---- Files ---------------------------------------------------------------
    ww = a.get("world_writable") or []
    if ww:
        findings.append(
            _f(
                "files-world-writable",
                "medium",
                f"{len(ww)} world-writable file(s) found (bounded scan)",
                ", ".join(ww[:10]),
                "Any local user or compromised service can modify them.",
                "Review manually - automatic changes could break applications.",
                "(manual)",
                "n/a",
            )
        )
    suid = a.get("suid") or []
    if suid:
        findings.append(
            _f(
                "files-suid",
                "info",
                f"{len(suid)} SUID binaries (bounded scan)",
                ", ".join(suid[:8]),
                "SUID programs run as their owner (often root); unexpected ones deserve a look.",
                "Informational only.",
                "(manual)",
                "n/a",
            )
        )
    loose = [
        m
        for m in a.get("file_modes", [])
        if _truthy(m.get("exists")) and mode_needs_tightening(m["mode"], m["desired"])
    ]
    if loose:
        findings.append(
            _f(
                "files-modes",
                "low",
                f"{len(loose)} sensitive file(s) have looser permissions than recommended",
                ", ".join(f"{m['path']} {m['mode']}->{tightened_mode(m['mode'], m['desired'])}" for m in loose[:10]),
                "Configuration files with secrets or cron entries should not be readable/writable by everyone.",
                "Remove the extra permission bits only (never adds bits; old modes saved for rollback).",
                "file_permissions_apply",
                "low",
            )
        )

    # ---- Services ------------------------------------------------------------
    failed = a.get("failed_units") or []
    if failed:
        findings.append(
            _f(
                "svc-failed",
                "medium",
                f"{len(failed)} failed systemd unit(s)",
                ", ".join(failed[:10]),
                "A failed unit can be a crashed mail/web component or a missing security service.",
                "Inspect with: systemctl status <unit> / journalctl -u <unit>.",
                "(manual)",
                "n/a",
            )
        )

    # ---- sysctl --------------------------------------------------------------
    cur = a.get("sysctl") or {}
    want = a.get("sysctl_desired") or {}
    diff_sys = {k: (cur.get(k, "?"), v) for k, v in want.items() if str(cur.get(k, "?")) != str(v)}
    if diff_sys:
        findings.append(
            _f(
                "sysctl-network",
                "low",
                f"{len(diff_sys)} network kernel setting(s) differ from conservative baseline",
                ", ".join(f"{k}: {c} -> {w}" for k, (c, w) in sorted(diff_sys.items())),
                "Ignoring ICMP redirects / source routing and logging martians makes spoofing harder.",
                "Write /etc/sysctl.d/60-server-hardening.conf (previous runtime values saved for rollback).",
                "sysctl_network_apply",
                "medium",
            )
        )

    # ---- Lynis ---------------------------------------------------------------
    if not _truthy(a.get("lynis_installed")):
        findings.append(
            _f(
                "lynis-missing",
                "info",
                "Lynis is not installed",
                "",
                "Lynis gives an independent hardening score to compare before/after.",
                "make lynis-before installs it (distro package) and runs an audit.",
                "lynis_apply",
                "low",
            )
        )

    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 9), f["id"]))
    return findings


def findings_summary(findings) -> dict:
    summary = {k: 0 for k in SEVERITY_ORDER}
    for f in findings or []:
        summary[f["severity"]] = summary.get(f["severity"], 0) + 1
    summary["total"] = sum(summary[k] for k in SEVERITY_ORDER)
    return summary


class FilterModule:
    """Expose the helpers to Ansible/Jinja2."""

    def filters(self):
        return {
            "parse_ss": parse_ss,
            "public_listeners": public_listeners,
            "firewall_plan": firewall_plan,
            "normalize_port_spec": normalize_port_spec,
            "sshd_effective": sshd_effective,
            "sshd_value": sshd_value,
            "sshd_mismatches": sshd_mismatches,
            "file_mode_plan": file_mode_plan,
            "state_file_name": state_file_name,
            "parse_sysctl": parse_sysctl,
            "parse_login_defs": parse_login_defs,
            "backup_category": backup_category,
            "rollback_actions": rollback_actions,
            "suggest_allowed_ports": suggest_allowed_ports,
            "authorized_keys_paths": authorized_keys_paths,
            "parse_passwd": parse_passwd,
            "system_accounts_with_shell": system_accounts_with_shell,
            "login_accounts": login_accounts,
            "mode_needs_tightening": mode_needs_tightening,
            "tightened_mode": tightened_mode,
            "md_cell": md_cell,
            "build_findings": build_findings,
            "findings_summary": findings_summary,
        }
