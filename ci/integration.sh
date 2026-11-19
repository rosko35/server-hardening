#!/usr/bin/env bash
# End-to-end test against the disposable container (see .github/workflows/ci.yml).
# This is the only place the playbooks really run. Each stage prints a
# collapsible log group, and every assertion prints PASS/FAIL with a reason.
#
#   1. audit changes nothing on the server
#   2. Lynis "before"
#   3. safety refusals: empty firewall allow list, unacknowledged mail port,
#      disabling passwords for a user without a key
#   4. --check --diff of every category changes nothing
#   5. apply every category, then apply again: second run must report changed=0
#   6. the server still works: sshd -t, NEW key login, web reachable, ...
#   7. Lynis "after" + comparison
#   8. rollback restores the original state
set -euo pipefail
cd "$(dirname "$0")/.."

: "${CI_PASSWORD:?CI_PASSWORD must be set}"
INV=ci/inventory.yml
LOGS=ci/logs
SUMMARY=${GITHUB_STEP_SUMMARY:-/dev/null}
HOSTNAME_IN_REPORTS=target
mkdir -p "$LOGS"
export ANSIBLE_NOCOLOR=1 ANSIBLE_FORCE_COLOR=0 PY_COLORS=0

APPLY_ALL=(-e @ci/vars-apply.yml
  -e ssh_hardening_apply=true -e firewall_apply=true -e auto_updates_apply=true
  -e fail2ban_apply=true -e sysctl_network_apply=true -e accounts_apply=true
  -e file_permissions_apply=true)

# ---------------------------------------------------------------- helpers ----
group() { echo "::group::$*"; }
endgroup() { echo "::endgroup::"; }
pass() { echo "PASS: $*"; echo "- ✅ $*" >> "$SUMMARY"; }
fail() { echo "::error::FAIL: $*"; echo "- ❌ $*" >> "$SUMMARY"; exit 1; }
on_target() { docker exec target "$@"; }
# grep that always reads its whole input (grep -q + pipefail can trip on SIGPIPE)
contains() { grep "$@" >/dev/null; }

play() { # play <logname> <ansible-playbook args...>
  local name=$1; shift
  echo "+ ansible-playbook -i $INV $*"
  set +e
  ansible-playbook -i "$INV" "$@" 2>&1 | tee "$LOGS/$name.log"
  local rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}

must_succeed() { # must_succeed <logname> <args...>
  local name=$1
  play "$@" || fail "$name: ansible-playbook failed (see the '$name' log group above)"
  python3 scripts/check_recap.py "$LOGS/$name.log" || fail "$name: failed/unreachable hosts"
}

must_refuse() { # must_refuse <logname> <expected text> <args...>
  local name=$1 pattern=$2; shift 2
  if play "$name" "$@"; then fail "$name: playbook should have refused but succeeded"; fi
  grep -q -- "$pattern" "$LOGS/$name.log" || fail "$name: refused, but without the expected message: $pattern"
  pass "$name: refused as expected ('$pattern')"
}

snapshot_etc() { # content + permissions of every file under /etc
  on_target bash -c 'find /etc -xdev -type f -print0 | sort -z | xargs -0 md5sum; find /etc -xdev -printf "%m %u %p\n" | sort' > "$1"
}

ssh_opts=(-p 2222 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10)
key_login() { ssh -i ci/.ssh/id_ed25519 -o BatchMode=yes "${ssh_opts[@]}" ciadmin@127.0.0.1 true; }
password_login() {
  sshpass -p "$CI_PASSWORD" ssh "${ssh_opts[@]}" -o PubkeyAuthentication=no \
    -o PreferredAuthentications=password,keyboard-interactive ciadmin@127.0.0.1 true
}
web_ok() { curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:8080/; }
mail_ok() { curl -fsS --max-time 5 -o /dev/null http://127.0.0.1:2587/; }

echo "## Integration: $(on_target sh -c '. /etc/os-release; echo $PRETTY_NAME')" >> "$SUMMARY"

# ------------------------------------------------------------- baseline ------
group "0. Baseline"
key_login || fail "baseline: key login"
password_login || fail "baseline: password login should work before hardening"
web_ok || fail "baseline: web on :80 not reachable"
mail_ok || fail "baseline: stand-in mail service on :587 not reachable"
ORIG_REDIRECTS=$(on_target sysctl -n net.ipv4.conf.all.accept_redirects)
pass "baseline: key + password login, web and mail reachable"
endgroup

# ------------------------------------------------------------- 1. audit ------
group "1. Audit (default settings) must not change the server"
snapshot_etc "$LOGS/etc-before-audit.txt"
must_succeed 01-audit site.yml
snapshot_etc "$LOGS/etc-after-audit.txt"
diff -u "$LOGS/etc-before-audit.txt" "$LOGS/etc-after-audit.txt" || fail "audit modified files under /etc"
test -s "reports/$HOSTNAME_IN_REPORTS/audit-report.md" || fail "audit-report.md missing"
python3 -c "import json,sys; d=json.load(open(sys.argv[1])); assert d['findings'], 'no findings'; print(d['summary'])" \
  "reports/$HOSTNAME_IN_REPORTS/audit-report.json" || fail "audit-report.json invalid"
grep -q "fw-would-close\|No active host firewall" "reports/$HOSTNAME_IN_REPORTS/audit-report.json" || fail "firewall finding missing"
pass "audit: report written, /etc untouched"
endgroup
{
  echo "<details><summary>Audit report (audit-report.md)</summary>"; echo
  cat "reports/$HOSTNAME_IN_REPORTS/audit-report.md"; echo; echo "</details>"
} >> "$SUMMARY"

# ---------------------------------------------------------- 2. lynis ---------
group "2. Lynis before"
must_succeed 02-lynis-before lynis.yml -e lynis_label=before -e lynis_apply=true
test -s "reports/$HOSTNAME_IN_REPORTS/lynis-before.dat" || fail "lynis-before.dat not fetched"
pass "lynis before: $(grep -o 'hardening_index=[0-9]*' "reports/$HOSTNAME_IN_REPORTS/lynis-before.dat")"
endgroup

# ------------------------------------------------------- 3. refusals ---------
group "3. Safety refusals"
snapshot_etc "$LOGS/etc-before-refusals.txt"
must_refuse 03a-firewall-empty "empty allow list" \
  site.yml --tags firewall -e firewall_apply=true
must_refuse 03b-firewall-mail-port "would be BLOCKED" \
  site.yml --tags firewall -e firewall_apply=true -e '{"firewall_allowed_ports": ["22/tcp", "80/tcp"]}'
must_refuse 03c-ssh-no-key "Refusing to disable password" \
  site.yml --tags ssh -e ssh_hardening_apply=true -e harden_operator_user=nokey
on_target test ! -e /etc/ssh/sshd_config.d/01-server-hardening.conf || fail "refused ssh run still wrote the drop-in"
on_target sh -c 'ufw status 2>/dev/null | grep -q "Status: active"' && fail "refused firewall run enabled ufw"
snapshot_etc "$LOGS/etc-after-refusals.txt"
# Installing the ufw package is allowed to happen before the refusal; config files must not change.
diff <(grep -v '/etc/ufw\|/etc/default/ufw\|/etc/rsyslog.d\|/etc/logrotate.d\|ld.so.cache\|/etc/systemd/system' "$LOGS/etc-before-refusals.txt") \
     <(grep -v '/etc/ufw\|/etc/default/ufw\|/etc/rsyslog.d\|/etc/logrotate.d\|ld.so.cache\|/etc/systemd/system' "$LOGS/etc-after-refusals.txt") \
  || fail "a refused run modified configuration under /etc"
pass "refusals left SSH and firewall untouched"
endgroup

# ------------------------------------------------------ 4. dry run -----------
group "4. --check --diff of every category"
snapshot_etc "$LOGS/etc-before-check.txt"
must_succeed 04-check site.yml "${APPLY_ALL[@]}" --check --diff
snapshot_etc "$LOGS/etc-after-check.txt"
diff -u "$LOGS/etc-before-check.txt" "$LOGS/etc-after-check.txt" || fail "--check modified files under /etc"
pass "check mode: no changes under /etc"
endgroup

# ------------------------------------------------- 5. apply + idempotence ----
group "5a. Apply every category"
on_target md5sum /etc/login.defs > "$LOGS/login.defs.orig.md5"
must_succeed 05a-apply site.yml "${APPLY_ALL[@]}"
pass "apply: first run succeeded"
endgroup

group "5b. Apply again - must report changed=0"
must_succeed 05b-idempotence site.yml "${APPLY_ALL[@]}"
python3 scripts/check_recap.py "$LOGS/05b-idempotence.log" --expect-changed 0 || fail "second apply was not idempotent"
pass "idempotence: second run changed=0"
endgroup

# --------------------------------------------- 6. server still works ---------
group "6. Post-apply checks"
on_target sshd -t || fail "sshd -t fails after hardening"
eff=$(on_target sshd -T)
grep -qx "passwordauthentication no" <<<"$eff" || fail "PasswordAuthentication not effective"
grep -qx "permitrootlogin no" <<<"$eff" || fail "PermitRootLogin not effective"
grep -qx "port 22" <<<"$eff" || fail "SSH port changed!"
key_login || fail "NEW key login fails after hardening (lock-out!)"
if password_login 2>/dev/null; then fail "password login still accepted"; fi
on_target ufw status | tee /dev/stderr | contains -E '^22/tcp +ALLOW' || fail "ufw has no SSH allow rule"
on_target ufw status | contains "Status: active" || fail "ufw not active"
web_ok || fail "website not reachable through the firewall"
if mail_ok 2>/dev/null; then fail "port 587 was acknowledged as closed but is still reachable"; fi
on_target fail2ban-client status sshd || fail "fail2ban sshd jail not running"
on_target fail2ban-client get sshd ignoreip | tee /dev/stderr | contains '172\.' || fail "operator IP not in ignoreip"
key_login || fail "key login fails after failed password attempts (operator banned?)"
on_target apt-config dump Unattended-Upgrade::Automatic-Reboot | contains '"false"' || fail "automatic reboot not false"
on_target apt-config dump Unattended-Upgrade::Origins-Pattern | contains -i security || fail "no security origin"
[ "$(on_target sysctl -n net.ipv4.conf.all.accept_redirects)" = 0 ] || fail "sysctl not applied"
on_target grep -Eq '^PASS_MAX_DAYS[[:space:]]+365' /etc/login.defs || fail "login.defs not updated"
on_target getent passwd svcdemo | contains nologin || fail "svcdemo shell not locked"
[ "$(on_target stat -c %a /etc/crontab)" = 600 ] || fail "/etc/crontab mode not tightened"
on_target test -f /var/backups/server-hardening/originals/etc/login.defs || fail "login.defs backup missing"
on_target test -f /var/backups/server-hardening/originals/etc/ssh/sshd_config.d/01-server-hardening.conf.absent \
  || fail "drop-in 'did not exist' marker missing"
pass "post-apply: sshd valid, new key login OK, passwords refused, web up, 587 filtered, backups present"
endgroup

# ----------------------------------------------------- 7. lynis after --------
group "7. Lynis after + comparison"
must_succeed 07-lynis-after lynis.yml -e lynis_label=after
python3 scripts/compare_lynis.py "reports/$HOSTNAME_IN_REPORTS/lynis-before.dat" "reports/$HOSTNAME_IN_REPORTS/lynis-after.dat" \
  | tee "$LOGS/lynis-comparison.md"
{ echo; echo "### Lynis in the CI container (not a real server)"; echo; cat "$LOGS/lynis-comparison.md"; } >> "$SUMMARY"
pass "lynis after + comparison"
endgroup

# --------------------------------------------------------- 8. rollback -------
group "8a. Rollback without confirmation only lists"
must_succeed 08a-rollback-list rollback.yml
python3 scripts/check_recap.py "$LOGS/08a-rollback-list.log" --expect-changed 0 || fail "unconfirmed rollback changed something"
on_target test -f /etc/ssh/sshd_config.d/01-server-hardening.conf || fail "unconfirmed rollback removed the drop-in"
pass "rollback without CONFIRM changed nothing"
endgroup

group "8b. Rollback"
must_succeed 08b-rollback rollback.yml -e rollback_confirm=true
on_target sshd -t || fail "sshd -t fails after rollback"
on_target test ! -e /etc/ssh/sshd_config.d/01-server-hardening.conf || fail "drop-in still present"
key_login || fail "key login fails after rollback"
password_login || fail "password login not restored by rollback"
on_target ufw status | contains "Status: inactive" || fail "ufw still active after rollback"
mail_ok || fail "port 587 not reachable after rollback"
on_target md5sum -c --quiet - < "$LOGS/login.defs.orig.md5" || fail "login.defs not restored"
[ "$(on_target stat -c %a /etc/crontab)" = 644 ] || fail "/etc/crontab mode not restored"
on_target getent passwd svcdemo | contains /bin/bash || fail "svcdemo shell not restored"
[ "$(on_target sysctl -n net.ipv4.conf.all.accept_redirects)" = "$ORIG_REDIRECTS" ] || fail "sysctl runtime value not restored"
on_target test ! -e /etc/fail2ban/jail.d/server-hardening.local || fail "fail2ban jail still present"
on_target test ! -e /etc/apt/apt.conf.d/52server-hardening-unattended || fail "unattended config still present"
pass "rollback: original SSH/firewall/login.defs/modes/shells/sysctl restored"
endgroup

echo "All integration stages passed."
