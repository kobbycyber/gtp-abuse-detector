# Live dashboard

A single-page, no-build dashboard that shows the detector working in real
time: a network topology (UE → gNB → N3/GTP-U → UPF, with the detector's
passive tap), live packet/GTP-U counters, a per-rule findings tally, and a
scrolling live findings feed. Someone who has never seen this project can
watch it for 30 seconds and understand what's being detected.

## How it works

`server.py` is a small Python **standard-library-only** HTTP server. It:

1. Runs `docker compose logs -f --no-log-prefix --tail 0 detector` as a
   subprocess — this is exactly the same JSON-lines stream the detector
   already produces (`docker-compose.yml` passes `--json` to it), nothing
   new is added to the detector's output format beyond a `"type"` tag
   (`"finding"` or `"heartbeat"`) so the browser can tell events apart.
2. Re-publishes every line to any number of connected browser tabs over
   Server-Sent Events (`/events`).
3. Serves `index.html` at `/`.

No new Docker service, no new dependency, no change to detection logic —
this is purely an observability layer on top of the detector's existing
output.

## Run it

While the lab is up (`../scripts/lab_up.sh`):

```bash
python3 viz/server.py            # defaults to :8090
# or: python3 viz/server.py --port 9000
```

Then open **http://localhost:8090** in a browser. It works even if you
start it *before* the lab is up — it shows a "waiting for detector…"
status pill and connects automatically once `docker compose logs` starts
producing lines.

To actually see something happen, fire the live attack corpus in another
terminal:

```bash
docker compose run --rm attacker --send --iface eth0 \
    --count 400 --benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20
```

You'll see the topology's N3 link flash in the finding's severity color,
the per-rule tally bars grow, and rows stream into the live feed table —
while benign traffic stays completely silent, which is the point (the
detector only speaks when something's wrong).

## Design notes

- Built against this project's validated default palette (fixed status
  colors for severity — critical/high — and a fixed categorical order for
  R1–R4, both direct-labeled so identity never rests on color alone).
- Dark/light mode both implemented (OS preference **and** the in-page
  toggle button, which wins over the OS setting either direction).
- The rule tally has a "view as table" toggle (the accessible twin of the
  bar chart); the live feed is already a real `<table>` with
  `aria-live="polite"` so new rows are announced.
- No frameworks, no build step, no external requests — everything is in
  `index.html` and served same-origin from `server.py`.
