.DEFAULT_GOAL := help
COMPOSE := docker compose

.PHONY: help
help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

# ---------------------------------------------------------------------------
# Offline science path (NO 5G core needed) — this produces thesis metrics.
# ---------------------------------------------------------------------------
.PHONY: test
test: ## Run detector unit tests (pytest)
	cd detector && python3 -m pytest tests/ -q

.PHONY: eval
eval: ## Full benchmark (realistic benign, baseline, ablation, evasions) -> eval/RESULTS.md
	python3 eval/run_eval.py --seeds 1337,1,2,3,4 --benign 600 --per-class 120

.PHONY: benign
benign: ## Write a realistic benign-only pcap to captures/ (no scoring)
	python3 attacker/benign_traffic.py --count 600 \
		--write captures/benign.pcap --labels-out captures/benign.labels.json \
		--categories-out captures/benign.cats.json

.PHONY: evasions
evasions: ## List the crafted evasion suite (what the detector must / can't catch)
	python3 attacker/evasions.py

.PHONY: score
score: ## Score an existing captures/mixed.pcap (legacy single-run path)
	python3 detector/gtpu_detector.py pcap --file captures/mixed.pcap \
		--labels captures/mixed.labels.json \
		--core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
		--metrics-out eval/metrics.json

# ---------------------------------------------------------------------------
# Live lab path (Docker) — runs on a host with a real kernel (your Proxmox VM).
# ---------------------------------------------------------------------------
.PHONY: build
build: ## Build all container images
	$(COMPOSE) build

.PHONY: lab-up
lab-up: ## Start core + RAN + live detector
	$(COMPOSE) up -d mongo core ran detector
	@echo "Detector logs:  make logs"

.PHONY: logs
logs: ## Follow detector output
	$(COMPOSE) logs -f detector

.PHONY: attack
attack: ## Fire the live attack corpus at the lab UPF
	$(COMPOSE) run --rm attacker --send --iface eth0 \
		--count 400 --benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20

.PHONY: shell-core
shell-core: ## Shell into the core container
	$(COMPOSE) exec core bash

.PHONY: lab-down
lab-down: ## Stop and remove the lab
	$(COMPOSE) down

.PHONY: clean
clean: ## Remove volumes and generated artifacts
	$(COMPOSE) down -v || true
	rm -f captures/*.pcap captures/*.labels.json eval/metrics.json eval/RESULTS.md
