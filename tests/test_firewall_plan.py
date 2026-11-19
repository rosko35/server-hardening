"""The firewall decision logic: the part most likely to lock someone out."""

import pytest
from hardening_filters import (
    AnsibleFilterError,
    firewall_plan,
    normalize_port_spec,
    parse_ss,
    public_listeners,
    suggest_allowed_ports,
)


@pytest.fixture
def listeners(ss_output):
    return parse_ss(ss_output)


# --------------------------------------------------------------------------- #
# parse_ss
# --------------------------------------------------------------------------- #
def test_parse_ss_merges_ipv4_and_ipv6_and_detects_programs(listeners):
    by_port = {(i["port"], i["proto"]): i for i in listeners}
    ssh = by_port[(22, "tcp")]
    assert ssh["process"] == "sshd"
    assert set(ssh["addresses"]) == {"0.0.0.0", "::"}
    assert ssh["public"] is True
    assert by_port[(993, "tcp")]["process"] == "dovecot"
    assert by_port[(25, "tcp")]["category"] == "mail"
    assert by_port[(443, "tcp")]["category"] == "web"


def test_parse_ss_marks_loopback_only_services_private(listeners):
    by_port = {(i["port"], i["proto"]): i for i in listeners}
    assert by_port[(3306, "tcp")]["public"] is False
    assert by_port[(8891, "tcp")]["public"] is False
    # 127.0.0.53%lo -> interface suffix stripped, still loopback
    assert by_port[(53, "tcp")]["public"] is False


def test_parse_ss_ignores_garbage_and_non_listening():
    out = parse_ss('garbage\n\ntcp ESTAB 0 0 10.0.0.1:22 10.0.0.2:5555 users:(("sshd",pid=1,fd=3))\n')
    assert out == []


def test_public_listeners_skip_udp_clients(listeners):
    specs = {(i["port"], i["proto"]) for i in public_listeners(listeners)}
    assert (68, "udp") not in specs  # DHCP client
    assert (22, "tcp") in specs
    assert (3306, "tcp") not in specs


# --------------------------------------------------------------------------- #
# Port spec validation
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "spec,expected",
    [
        (22, ("22", "tcp")),
        ("443/tcp", ("443", "tcp")),
        ("53/udp", ("53", "udp")),
        ("60000:61000/udp", ("60000:61000", "udp")),
        (" 80/TCP ", ("80", "tcp")),
    ],
)
def test_normalize_port_spec(spec, expected):
    r = normalize_port_spec(spec)
    assert (r["port"], r["proto"]) == expected


@pytest.mark.parametrize("spec", ["", "ssh", "0", "70000", "22/icmp", "100:50/tcp", "22/tcp/extra"])
def test_normalize_port_spec_rejects_bad_input(spec):
    with pytest.raises(AnsibleFilterError):
        normalize_port_spec(spec)


# --------------------------------------------------------------------------- #
# firewall_plan safety rules
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("empty", [[], None, ()])
def test_empty_allow_list_is_refused_in_strict_mode(listeners, empty):
    with pytest.raises(AnsibleFilterError, match="empty"):
        firewall_plan(listeners, empty, 22)


def test_empty_allow_list_is_reported_in_preview_mode(listeners):
    plan = firewall_plan(listeners, [], 22, strict=False)
    assert plan["ok"] is False
    assert any("empty" in e for e in plan["errors"])


def test_ssh_port_is_always_the_first_rule_even_if_forgotten(listeners):
    plan = firewall_plan(listeners, ["80/tcp", "443/tcp"], 22, acknowledged_closing=["25", "465", "587", "993"])
    assert plan["rules"][0]["port"] == "22"
    assert plan["rules"][0]["proto"] == "tcp"
    assert any("added automatically" in w for w in plan["warnings"])


def test_custom_ssh_port_comes_first(listeners):
    plan = firewall_plan([], ["2222/tcp", "80/tcp"], "2222", strict=False)
    assert [r["port"] for r in plan["rules"]] == ["2222", "80"]  # no duplicate


def test_unknown_ssh_port_is_refused(listeners):
    with pytest.raises(AnsibleFilterError, match="SSH port"):
        firewall_plan(listeners, ["80/tcp"], "")


def test_mail_ports_that_would_close_raise_loud_warning_and_refusal(listeners):
    allowed = ["22/tcp", "80/tcp", "443/tcp"]
    preview = firewall_plan(listeners, allowed, 22, strict=False)
    closing = {w["spec"] for w in preview["would_close"]}
    assert closing == {"25/tcp", "465/tcp", "587/tcp", "993/tcp"}
    assert all(w["category"] == "mail" for w in preview["would_close"])
    assert any(w.startswith("!!!") and "mail" in w for w in preview["warnings"])
    assert preview["ok"] is False
    with pytest.raises(AnsibleFilterError, match="would be blocked"):
        firewall_plan(listeners, allowed, 22)


def test_acknowledged_closing_is_accepted(listeners):
    plan = firewall_plan(
        listeners, ["22/tcp", "80/tcp", "443/tcp"], 22, acknowledged_closing=["25/tcp", 465, "587", "993/tcp"]
    )
    assert plan["ok"] is True
    assert plan["unacknowledged"] == []
    assert all(w["acknowledged"] for w in plan["would_close"])


def test_full_mail_and_web_allow_list_closes_nothing(listeners):
    allowed = ["22/tcp", "80/tcp", "443/tcp", "25/tcp", "465/tcp", "587/tcp", "993/tcp"]
    plan = firewall_plan(listeners, allowed, 22)
    assert plan["ok"] is True
    assert plan["would_close"] == []
    assert [r["port"] for r in plan["rules"]] == ["22", "80", "443", "25", "465", "587", "993"]


def test_port_range_covers_listener():
    lst = [{"proto": "udp", "port": 60001, "addresses": ["0.0.0.0"], "process": "mosh", "public": True}]
    lst[0]["category"] = "other"
    plan = firewall_plan(lst, ["60000:61000/udp"], 22)
    assert plan["would_close"] == []


def test_invalid_entry_in_allow_list_is_an_error(listeners):
    plan = firewall_plan(listeners, ["80/tcp", "http"], 22, strict=False)
    assert plan["ok"] is False
    assert any("Invalid port" in e for e in plan["errors"])


def test_allowed_but_not_listening_is_a_warning(listeners):
    plan = firewall_plan(
        listeners, ["22/tcp", "8443/tcp"], 22, acknowledged_closing=["80", "443", "25", "465", "587", "993"]
    )
    assert any("8443/tcp is allowed but nothing listens" in w for w in plan["warnings"])


def test_suggested_allowed_ports_start_with_ssh(listeners):
    suggestion = suggest_allowed_ports(listeners, 22)
    assert suggestion[0] == "22/tcp"
    assert "993/tcp" in suggestion
    assert "3306/tcp" not in suggestion
    assert "68/udp" not in suggestion
