#!/usr/bin/env bash
#
# lab_up.sh -- bring the gtpu-abuse-lab live Docker stack up cleanly.
#
# Bakes in fixes for every ordering/race issue found while first bringing
# this lab up live (full root-cause writeups in paper/FINDINGS.md):
#   - ran's gNB attempts NGAP exactly once at container start and does not
#     retry; if core's AMF isn't listening yet, ran needs one restart.
#   - detector/attacker use network_mode: service:core, which resolves at
#     THEIR start time -- they must not be started until core is already
#     fully healthy, or they attach to nothing.
#
# Usage:
#   ./scripts/lab_up.sh            # build + bring up everything
#   ./scripts/lab_up.sh --no-build # skip the build step (images already built)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

SKIP_BUILD=0
if [[ "${1:-}" == "--no-build" ]]; then
    SKIP_BUILD=1
fi

# Transparently work whether or not the current shell session already has
# docker-group membership (see paper/REPRODUCE.md B.1) -- avoids forcing a
# fresh login just to run this script.
dc() {
    if docker info >/dev/null 2>&1; then
        docker compose "$@"
    else
        sg docker -c "docker compose $(printf '%q ' "$@")"
    fi
}

wait_for_log() {
    # wait_for_log <service> <pattern> <timeout_seconds>
    # Always returns 0 -- a timeout is a warning, not a fatal error, and
    # must not trip the script's `set -e` (a bug in an earlier version of
    # this script: a bare non-zero return from a call site killed the
    # whole run instead of "continuing anyway" as advertised).
    local service="$1" pattern="$2" timeout="${3:-60}" start
    start=$(date +%s)
    while true; do
        if dc logs "$service" 2>&1 | grep -q "$pattern"; then
            return 0
        fi
        if [ $(( $(date +%s) - start )) -ge "$timeout" ]; then
            echo "    WARNING: '$pattern' not seen in $service logs within ${timeout}s -- continuing anyway."
            echo "    Check manually: docker compose logs $service"
            return 0
        fi
        sleep 3
    done
}

echo "==> [1/6] Docker access check"
if ! docker info >/dev/null 2>&1; then
    echo "    current shell isn't in the 'docker' group yet -- using 'sg docker' wrapper for every command."
fi

if [ "$SKIP_BUILD" -eq 0 ]; then
    echo "==> [2/6] Building images (core, ran, detector, attacker)"
    dc build
    dc --profile tools build attacker
else
    echo "==> [2/6] Skipping build (--no-build)"
fi

echo "==> [3/6] Starting mongo + core, waiting for core to finish NF bring-up"
dc up -d mongo core
wait_for_log core "all NFs launched" 180
echo "    core is up."

echo "==> [4/6] Starting ran + detector"
dc up -d ran detector

echo "==> [5/6] Checking whether ran's first NG Setup attempt raced core's AMF"
sleep 8
if dc logs ran 2>&1 | tail -8 | grep -q "Connection refused"; then
    echo "    it raced -- restarting ran once (this is expected on a cold start)"
    dc restart ran
fi
echo "    waiting for PDU session establishment (uesimtun0)..."
wait_for_log ran "TUN interface" 120

echo "==> [6/6] Re-attaching detector to guarantee a fresh core-netns handle"
dc up -d --force-recreate detector

echo
echo "----------------------------------------------------------------------"
echo " Lab is up."
echo "----------------------------------------------------------------------"
echo "  docker compose ps                      # confirm all 4 services Up"
echo "  docker compose logs -f detector         # watch for findings live"
echo "  docker compose exec ran ./build/nr-binder \$(docker compose logs ran \\"
echo "      | grep -oE '10\\.45\\.[0-9]+\\.[0-9]+' | tail -1) ping -c3 8.8.8.8"
echo "                                           # prove real N3 traffic works"
echo "  docker compose run --rm attacker --send --iface eth0 \\"
echo "      --count 400 --benign 100 --upf 10.10.10.10 --smf 10.10.10.11 --gnb 10.10.10.20"
echo "                                           # fire the live attack corpus"
echo "  ./scripts/lab_down.sh                   # tear down when finished"
echo "----------------------------------------------------------------------"
