# Thin wrapper over sdr.py. The Python entry point is the real one; this file
# exists because `make` is muscle memory for a lot of people.
#
# Override the interpreter if you need to: make all PYTHON=python3.12

PYTHON ?= python

.DEFAULT_GOAL := help
.PHONY: help install install-locked all build validate scan clean reproducible catalog lock lock-security

help: ## Show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  %-14s %s\n", $$1, $$2}'

install: ## Install runtime dependencies from requirements.txt
	$(PYTHON) -m pip install -r requirements.txt

install-locked: ## Install the hash-verified closure CI uses (requirements.lock; Python 3.11+)
	$(PYTHON) -m pip install --require-hashes -r requirements.lock

lock: ## Resolve a fully-hashed requirements.lock, then rebuild the SBOM from it
	@echo "Resolving the full dependency closure with hashes into requirements.lock."
	@echo "Run this in a CLEAN environment with network access (not the offline"
	@echo "build sandbox), so the resolved versions are correct and complete."
	uv pip compile requirements.txt requirements-ci.txt --generate-hashes \
		--python-platform linux --python-version 3.12 --no-header \
		--output-file requirements.lock
	$(PYTHON) validation/scripts/build_sbom.py
	@echo "requirements.lock written and SBOM regenerated from the resolved closure."
	@echo "Commit requirements.lock and the regenerated artifacts/sbom.cdx.json together."

lock-security: ## Resolve the hash-locked closure of the security-gate tools (Bandit, pip-audit)
	@echo "Resolving requirements-security.txt into requirements-security.lock with hashes,"
	@echo "constrained to requirements.lock so a shared transitive cannot diverge."
	uv pip compile requirements-security.txt -c requirements.lock --generate-hashes \
		--python-platform linux --python-version 3.12 --no-header \
		--output-file requirements-security.lock
	@echo "requirements-security.lock written. Commit it with requirements-security.txt."

all: ## Build, validate, scan, then print a readiness summary
	$(PYTHON) sdr.py all

build: ## Regenerate every deliverable from the record store
	$(PYTHON) sdr.py build

validate: ## Run the build gate; 0 hard failures required to ship
	$(PYTHON) sdr.py validate

scan: ## Run the readiness scanner (reports, does not gate)
	$(PYTHON) sdr.py scan

clean: ## Remove caches and scanner reports
	$(PYTHON) sdr.py clean

catalog: ## Regenerate the scanner check catalog after editing checks.py
	$(PYTHON) automation/sdrscan/sdrscan.py --write-catalog

reproducible: ## Prove the deliverables match their inputs (the CI gate, locally)
	$(PYTHON) sdr.py build
	@git diff --exit-code -- . ':(exclude)*.docx' \
		&& echo "OK. Every generated file matches what the pipeline produces." \
		|| { echo "FAIL. A generated file was hand-edited. Edit the record store instead."; exit 1; }
