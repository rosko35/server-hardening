# Thin wrapper around ansible-playbook. Every target prints the exact command
# it runs, so you can also copy it and run it by hand.
#
#   make audit                      # read-only audit + report (default target)
#   make apply-ssh CHECK=1          # dry run: show what WOULD change (--check --diff)
#   make apply-ssh                  # apply one category
#   make lynis-before / lynis-after / compare
#   make rollback                   # list what would be restored
#   make rollback CONFIRM=1 CATEGORIES=ssh
#
# Options:
#   LOCAL=1          run on this machine (repo cloned on the server, -c local)
#   INVENTORY=path   default inventory/hosts.yml
#   K=0              do not ask for the sudo password (-K); default asks
#   CHECK=1          add --check --diff (dry run)
#   EXTRA='...'      extra ansible-playbook arguments, e.g. EXTRA='-e harden_operator_ip=1.2.3.4'
#   HOST=name        host name used for report paths (compare target)

.DEFAULT_GOAL := audit
SHELL := /bin/bash

ifeq ($(LOCAL),1)
INVENTORY ?= inventory/localhost.yml
HOST ?= localhost
else
INVENTORY ?= inventory/hosts.yml
HOST ?= mail
endif

K ?= 1
CHECK ?= 0
CONFIRM ?= 0
CATEGORIES ?= all
EXTRA ?=
PYTHON ?= python3

BECOME_FLAG := $(if $(filter 1,$(K)),--ask-become-pass,)
DRY_FLAG := $(if $(filter 1,$(CHECK)),--check --diff,)
PLAYBOOK := ansible-playbook -i $(INVENTORY) $(BECOME_FLAG) $(DRY_FLAG) $(EXTRA)

define run
	@echo "+ $(1)"
	@$(1)
endef

.PHONY: help audit apply-ssh apply-firewall apply-auto-updates apply-fail2ban apply-sysctl \
        apply-accounts apply-file-permissions lynis-before lynis-after compare rollback \
        syntax lint test check-inventory

help:
	@sed -n '1,20p' Makefile

check-inventory:
	@test -f $(INVENTORY) || { echo "Inventory $(INVENTORY) not found. Copy inventory/hosts.example.yml to inventory/hosts.yml, or use LOCAL=1."; exit 1; }

# ---- audit (read-only) -------------------------------------------------------
audit: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags audit)

# ---- one category at a time --------------------------------------------------
apply-ssh: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags ssh -e ssh_hardening_apply=true)

apply-firewall: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags firewall -e firewall_apply=true)

apply-auto-updates: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags auto_updates -e auto_updates_apply=true)

apply-fail2ban: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags fail2ban -e fail2ban_apply=true)

apply-sysctl: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags sysctl -e sysctl_network_apply=true)

apply-accounts: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags accounts -e accounts_apply=true)

apply-file-permissions: check-inventory
	$(call run,$(PLAYBOOK) site.yml --tags file_permissions -e file_permissions_apply=true)

# ---- Lynis score -------------------------------------------------------------
lynis-before: check-inventory
	$(call run,$(PLAYBOOK) lynis.yml -e lynis_label=before -e lynis_apply=true)

lynis-after: check-inventory
	$(call run,$(PLAYBOOK) lynis.yml -e lynis_label=after)

compare:
	$(call run,$(PYTHON) scripts/compare_lynis.py reports/$(HOST)/lynis-before.dat reports/$(HOST)/lynis-after.dat)

# ---- rollback ----------------------------------------------------------------
rollback: check-inventory
	$(call run,$(PLAYBOOK) rollback.yml -e rollback_confirm=$(if $(filter 1,$(CONFIRM)),true,false) -e rollback_categories=$(CATEGORIES))

# ---- development -------------------------------------------------------------
syntax:
	$(call run,ansible-playbook -i inventory/localhost.yml --syntax-check site.yml lynis.yml rollback.yml)

lint:
	yamllint -s .
	ruff check .
	ansible-lint

test:
	$(PYTHON) -m pytest
