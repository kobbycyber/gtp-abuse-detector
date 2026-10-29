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

.PHONY: live-score
live-score: ## Write the exact `make attack` corpus with labels and score it per packet
	python3 attacker/generate_attacks.py --count 400 --benign 100 \
		--upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20 \
		--write captures/live_corpus.pcap --labels-out captures/live_corpus.labels.json
	python3 detector/gtpu_detector.py pcap --file captures/live_corpus.pcap \
		--labels captures/live_corpus.labels.json \
		--core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
		--metrics-out captures/live_corpus.metrics.json

# ---------------------------------------------------------------------------
# Held-out, independent-data and comparator evaluation (revised manuscript)
# ---------------------------------------------------------------------------
DATA ?= $(HOME)/5g-cgad

.PHONY: heldout
heldout: ## Held-out seeds 101-110, plain and realistic outer header -> eval/results/
	python3 eval/heldout.py --out eval/results/heldout_plain.json
	python3 eval/heldout.py --realistic-outer --out eval/results/heldout_ext.json

.PHONY: latency
latency: ## Per-packet cost, five passes -> eval/results/latency.json
	python3 eval/latency.py --reps 5 --out eval/results/latency.json

.PHONY: fetch-data
fetch-data: ## Download the Oulu 5G-CGAD captures into $(DATA) (~6.9 GB)
	scripts/revision2/fetch_5gcgad.sh $(DATA)

.PHONY: external
external: ## Score engine + baseline on 5G-CGAD in $(DATA) -> eval/results/external/
	scripts/revision2/run_external.sh $(DATA) attacks
	scripts/revision2/run_external.sh $(DATA) benign

.PHONY: comparators
comparators: ## Zeek, Suricata and tshark on per-class captures (Docker) -> comparators/
	scripts/revision2/run_comparators.sh comparators

.PHONY: figures
figures: ## Regenerate manuscript figures -> paper/figures/manuscript/
	cd paper/figures && python3 make_manuscript_figures.py

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

.PHONY: live-run
live-run: ## Labelled live run with real UE traffic: make live-run TAG=L1 SEED=2026 TEID=0x2 COUNT=400 BENIGN=100
	scripts/revision2/run_live.sh $(TAG) $(SEED) $(TEID) $(COUNT) $(BENIGN)

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
	find captures -maxdepth 1 -type f ! -name .gitkeep ! -name dissector_probe.pcap -delete
	rm -f eval/metrics.json eval/RESULTS.md
	rm -rf comparators eval/results/external eval/results/live eval/results/*.json
