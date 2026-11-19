# Beginner's guide: from zero to a hardened server

🇹🇷 [Türkçe](REHBER.tr.md)

This guide assumes you can SSH into your server and nothing else. No Ansible knowledge needed.
Every command has a one-line explanation, what you should see, and what to do if it goes wrong.

**The plan:** audit → read the report → Lynis "before" → apply **one** safe category at a time
(dry run first) → Lynis "after" → compare.

Contents

1. [Before you start: two safety habits](#1-before-you-start-two-safety-habits)
2. [Pick how you will run it](#2-pick-how-you-will-run-it)
3. [Way A – local mode (on the server, simplest)](#3-way-a--local-mode-on-the-server-simplest)
4. [Way B – from Windows with WSL](#4-way-b--from-windows-with-wsl)
5. [Run the audit](#5-run-the-audit)
6. [Read the report](#6-read-the-report)
7. [Lynis "before"](#7-lynis-before)
8. [Apply one category at a time](#8-apply-one-category-at-a-time)
9. [Lynis "after" and compare](#9-lynis-after-and-compare)
10. [If something goes wrong](#10-if-something-goes-wrong)
11. [Glossary](#11-glossary)

---

## 1. Before you start: two safety habits

1. **Keep a second SSH session open** while you apply anything to SSH or the firewall.
   An already open session survives an sshd reload and a firewall change. If the new settings
   break logins, you fix them from that session.
2. **Find your provider's web console now, not when you need it.** Every VPS provider
   (Hetzner, DigitalOcean, Contabo, OVH, ...) has a "Console" / "VNC" / "Rescue" button in their
   web panel that gives you a terminal *without SSH*. Open it once and check that you can log in.
   For that you need a **password** for your user (the console does not use SSH keys).
   If you do not know it, set one now:

   ```bash
   sudo passwd $USER        # sets a password for your user; used for sudo and the web console
   ```

## 2. Pick how you will run it

Ansible is the tool that runs the checks and changes. It does **not** run natively on Windows.

| | Way A: local mode | Way B: WSL on Windows |
|---|---|---|
| Where Ansible runs | on the server itself | in Linux inside Windows |
| Setup effort | one `apt install` | install WSL + Ansible |
| Recommended for | one server, first time | several servers, keeping reports on your laptop |

If unsure: **Way A**.

## 3. Way A – local mode (on the server, simplest)

```bash
ssh emre@your-server                       # log in as your normal sudo user (NOT root)
```
You should see your server's prompt, e.g. `emre@mail:~$`.

```bash
sudo apt update                            # refresh the package list
sudo apt install -y ansible git make       # install Ansible (+ git to download, make for shortcuts)
ansible --version                          # check it works
```
Expected: `ansible [core 2.16.x]` or similar. If `apt` says "Could not get lock", another update
is running – wait a few minutes and retry.

```bash
cd ~
git clone https://github.com/rosko35/server-hardening.git    # download this project
cd server-hardening
```

From now on every command gets `LOCAL=1`, which tells the Makefile to use `inventory/localhost.yml`
(Ansible manages the machine it runs on, `-c local`, no SSH involved).

**What is `-K`?** Ansible needs root rights for most checks, and gets them with `sudo`.
`-K` (long form `--ask-become-pass`) makes Ansible ask for your sudo password once at the start:

```text
BECOME password:
```

Type your user's password (nothing appears while typing – that is normal) and press Enter.
The Makefile adds `-K` automatically. If your sudo never asks for a password, add `K=0`.

> Do **not** run `sudo make ...` or `sudo ansible-playbook ...`. Run as your normal user and let `-K` handle sudo.
> Otherwise the project cannot see who you are and where you connect from, and it will refuse the SSH/fail2ban steps.

> If you use `tmux` or `screen`, your connection IP may not be visible. The fail2ban step will tell you and ask for
> `EXTRA='-e harden_operator_ip=YOUR.IP'`. Find your IP with `echo $SSH_CLIENT` in a plain SSH session (first field).

Continue with [5. Run the audit](#5-run-the-audit).

## 4. Way B – from Windows with WSL

WSL ("Windows Subsystem for Linux") runs a real Ubuntu inside Windows.

1. Open **PowerShell as Administrator** (Start → type "PowerShell" → right-click → Run as administrator):

   ```powershell
   wsl --install -d Ubuntu-24.04       # installs WSL and Ubuntu 24.04
   ```
   Reboot when asked. After the reboot an Ubuntu window opens and asks for a new UNIX username
   and password – this is only for WSL, it can differ from your server.

2. In the Ubuntu (WSL) window:

   ```bash
   sudo apt update && sudo apt install -y ansible git make openssh-client   # tools
   cd ~                                                                       # your Linux home
   git clone https://github.com/rosko35/server-hardening.git
   cd server-hardening
   ```
   **Clone inside your Linux home (`~`), not under `/mnt/c/...`.** Windows folders are world-writable from
   Linux's point of view, and Ansible then silently ignores `ansible.cfg`.

3. Your SSH key: if your key lives in Windows (`C:\Users\you\.ssh\id_ed25519`), copy it into WSL:

   ```bash
   mkdir -p ~/.ssh && cp /mnt/c/Users/<you>/.ssh/id_ed25519* ~/.ssh/   # copy the key pair
   chmod 600 ~/.ssh/id_ed25519                                          # ssh refuses keys others can read
   ssh -i ~/.ssh/id_ed25519 emre@your-server true && echo OK            # test: should print OK
   ```

4. Tell Ansible about your server:

   ```bash
   cp inventory/hosts.example.yml inventory/hosts.yml    # your private copy (git-ignored)
   nano inventory/hosts.yml                              # edit: ansible_host, ansible_user, ansible_port
   ```
   Save with `Ctrl+O`, Enter, exit with `Ctrl+X`.

5. Test the connection:

   ```bash
   ansible -i inventory/hosts.yml hardening_targets -m ping     # ask the server "are you there?"
   ```
   Expected: `mail | SUCCESS => { "ping": "pong" }`. If you see `Host key verification failed`, SSH into the
   server once by hand (`ssh emre@your-server`) and answer `yes`, then retry.

In Way B leave out `LOCAL=1` in all commands below; reports land in `reports/mail/` (the host name from your inventory).

## 5. Run the audit

```bash
make audit LOCAL=1          # Way A
make audit                  # Way B
```
What it does: reads the server (listening ports, SSH config, users, updates, firewall, ...) and writes a report.
**It changes nothing.** The first line printed is the exact command, e.g.
`+ ansible-playbook -i inventory/localhost.yml --ask-become-pass site.yml --tags audit`.

Expected output: many green `ok:` lines and some `skipping:` lines, then a summary like

```text
TASK [Audit | Summary]
ok: [localhost] => msg:
  - Findings: 0 critical, 4 high, 5 medium, 6 low, 2 info
  - Report: .../reports/localhost/audit-report.md
...
PLAY RECAP
localhost : ok=60  changed=0  unreachable=0  failed=0  skipped=25
```

`changed=0` confirms nothing on the server was modified. If you see red `fatal:` lines, see [section 10](#10-if-something-goes-wrong).

## 6. Read the report

```bash
less reports/localhost/audit-report.md      # q to quit; Way B: reports/mail/audit-report.md
```

- **Summary**: counts by severity.
- **Findings** table: *What* was found, *Why it matters*, *How this project fixes it*, which **toggle** does it,
  and the **change risk** (how careful you should be when applying it).
- **Listening services**: every port, which program owns it, whether it is reachable from the internet.
  On a web + mail server you expect `22` (sshd), `80/443` (nginx), `25/465/587/993` (postfix/dovecot).
  Anything else public deserves a question.
- **Firewall plan**: a suggested `firewall_allowed_ports` list built from what is listening.
- `audit-report.json` contains the same data for scripts.

Tip: in Way B open the Markdown file in VS Code (`code reports/mail/audit-report.md`) for a nicer view.

## 7. Lynis "before"

Lynis is an independent auditing tool that gives a "hardening index" from 0 to 100. Measure *before* changing anything:

```bash
make lynis-before LOCAL=1        # installs the lynis package if missing, then scans (1–3 minutes)
```
Expected at the end: `Lynis hardening index (before): NN / 100`.
Files: `reports/<host>/lynis-before.dat` (raw) and `lynis-before.md` (readable).
The only change to the server is installing the `lynis` package (and its report in `/var/log/server-hardening/`).

## 8. Apply one category at a time

The pattern for **every** category is the same:

```bash
make apply-<category> LOCAL=1 CHECK=1   # 1. dry run: shows what WOULD change (--check --diff), changes nothing
make apply-<category> LOCAL=1           # 2. apply for real
make audit LOCAL=1                      # 3. re-audit: the finding should be gone
```

In the dry run, lines starting with `+` in a diff are what would be added, `-` what would be removed.
Read them. If something surprises you, stop and ask before applying.

Suggested order (lowest risk first):

### 8.1 Automatic security updates – risk: low

```bash
make apply-auto-updates LOCAL=1 CHECK=1
make apply-auto-updates LOCAL=1
```
Installs `unattended-upgrades`, restricted to security updates, **never reboots**.
Check: `sudo unattended-upgrade --dry-run -d 2>&1 | tail` shows what it would install.

### 8.2 File permissions – risk: low

```bash
make apply-file-permissions LOCAL=1 CHECK=1
make apply-file-permissions LOCAL=1
```
Only ever removes permission bits (e.g. `/etc/crontab` 644 → 600). Old modes are saved for rollback.

### 8.3 fail2ban – risk: low/medium

```bash
make apply-fail2ban LOCAL=1 CHECK=1
make apply-fail2ban LOCAL=1
```
Bans IPs after 5 failed SSH logins in 10 minutes, for 1 hour. Your current IP is never banned.
Check: `sudo fail2ban-client status sshd`.

### 8.4 SSH – risk: HIGH, read this first

Before: open a **second SSH session** to the server and leave it alone.

```bash
make apply-ssh LOCAL=1 CHECK=1    # the diff shows the new /etc/ssh/sshd_config.d/01-server-hardening.conf
make apply-ssh LOCAL=1
```
If the playbook prints `SSH changes are BLOCKED` it has refused on purpose – read the reason
(usually: no SSH key found for your user, so it will not turn off password login).

After it finishes, **from your laptop, open a third, new SSH session.** Only if that works, close the extra ones.

### 8.5 Firewall – risk: HIGH, read this first

1. Look at the "Firewall plan" section of the audit report and its suggested list.
2. Put the list into your host's variables. Way B: in `inventory/hosts.yml` under your host.
   Way A: create `host_vars/localhost.yml`:

   ```yaml
   ---
   firewall_allowed_ports: ["22/tcp", "80/tcp", "443/tcp", "25/tcp", "465/tcp", "587/tcp", "993/tcp"]
   ```
   Keep every port your website and mail need. Remove only what must not be reachable from the internet.
3. Second SSH session open, then:

   ```bash
   make apply-firewall LOCAL=1 CHECK=1   # prints the exact ufw commands and any port that would be BLOCKED
   make apply-firewall LOCAL=1
   ```
   If a listening port is not in your list, the role **refuses** and names the port and program.
   Either add it to `firewall_allowed_ports`, or – only if you really want it closed – add it to `firewall_acknowledge_closing`.
4. Test from outside: a new SSH login, open your website, send and receive one e-mail.

### 8.6 Network sysctl and accounts – risk: medium/low

```bash
make apply-sysctl LOCAL=1 CHECK=1     # read the diff first
make apply-sysctl LOCAL=1
make apply-accounts LOCAL=1 CHECK=1   # read the diff first
make apply-accounts LOCAL=1
```
`apply-accounts` only changes defaults for *new* accounts. Locking the shells of system accounts is a second,
separate switch (`EXTRA='-e accounts_lock_system_shells=true'`) – leave it until you have read the list in the report.

## 9. Lynis "after" and compare

```bash
make lynis-after LOCAL=1                 # same scan again
make compare HOST=localhost              # Way B: make compare (HOST defaults to "mail")
```
Expected: a table like

```text
| Metric | Before | After | Change |
|---|---:|---:|---:|
| **Lynis hardening index** | NN | MM | **+X** |
```
`reports/<host>/lynis-comparison.md` holds the same table plus which warnings/suggestions were resolved.
Paste it into the README "Results" section.

## 10. If something goes wrong

**The playbook stopped with a red `fatal:` / `FAILED!`.** Read the `msg:` – the safety checks explain themselves
("Nothing was changed. ..."). A refused step has changed nothing. For SSH, a failed validation restores the old file
automatically and sshd is not reloaded.

**"BECOME password" is wrong / `Missing sudo password`.** You typed the wrong password, or you used `K=0` but sudo needs one.

**Undo one category:**

```bash
make rollback LOCAL=1                               # lists what would be restored (changes nothing)
make rollback LOCAL=1 CONFIRM=1 CATEGORIES=ssh      # restore only SSH
make rollback LOCAL=1 CONFIRM=1                     # restore everything
```

**New SSH logins fail, but your second session is still open.** In that session:

```bash
sudo rm /etc/ssh/sshd_config.d/01-server-hardening.conf   # remove the hardening drop-in
sudo sshd -t && sudo systemctl reload ssh                  # validate, then reload
sudo ufw disable                                           # if the firewall is the problem
```

**You are completely locked out (no session open).** Use the provider's web console (section 1):

1. Log in to the provider's control panel → your server → **Console** (sometimes "VNC", "KVM", "Recovery console").
2. Log in with your user name and **password** (the console is like a keyboard attached to the server; keys do not apply).
3. Run the three commands above (`rm` the drop-in, `sshd -t && systemctl reload ssh`, `ufw disable`).
4. Try SSH again from your laptop. Then run `make rollback ... CONFIRM=1` or investigate.

If you also have no password: most providers offer a **rescue system** – boot it from the panel, mount your disk,
and delete `/etc/ssh/sshd_config.d/01-server-hardening.conf` (and set `ENABLED=no` in `/etc/ufw/ufw.conf`).

**Your own IP got banned by fail2ban** (e.g. home IP changed): from the console or another IP,
`sudo fail2ban-client set sshd unbanip YOUR.IP`.

**Mail or website stopped after the firewall:** `sudo ufw status numbered` shows the rules; `sudo ufw allow 587/tcp`
fixes one port immediately; then add it to `firewall_allowed_ports` so the next run keeps it.

## 11. Glossary

| Term | Meaning |
|---|---|
| Ansible | Tool that runs a list of tasks ("playbook") against servers and reports what changed. |
| Playbook | A YAML file with tasks, e.g. `site.yml`. |
| Role | A reusable folder of tasks for one topic, e.g. `roles/firewall/`. |
| Inventory | The list of servers to manage (`inventory/*.yml`). |
| `--check --diff` | Dry run: show what would change, change nothing. |
| `-K` | Ask for the sudo password once. |
| Idempotent | Running it twice changes nothing the second time. |
| Drop-in | A small extra config file in a `*.d/` folder that overrides the main file. |
| `sshd -t` | Checks the SSH server configuration for errors without applying it. |
| reload vs restart | reload re-reads config and keeps existing sessions; restart stops everything first. |
| ufw | "Uncomplicated firewall", the standard firewall front-end on Ubuntu. |
| Lynis | Independent security auditing tool that gives a 0–100 hardening index. |
