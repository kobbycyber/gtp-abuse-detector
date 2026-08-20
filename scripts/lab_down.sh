#!/usr/bin/env bash
#
# lab_down.sh -- tear down the gtpu-abuse-lab live Docker stack.
#
# Usage:
#   ./scripts/lab_down.sh          # stop + remove containers, keep volumes
#                                   # (mongo subscriber DB, captures/ survive)
#   ./scripts/lab_down.sh --clean  # also wipe volumes (fresh subscriber DB
#                                   # next time, captures/ wiped)
#
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

dc() {
    if docker info >/dev/null 2>&1; then
        docker compose "$@"
    else
        sg docker -c "docker compose $(printf '%q ' "$@")"
    fi
}

if [[ "${1:-}" == "--clean" ]]; then
    echo "==> Stopping and removing containers + volumes"
    dc down -v
else
    echo "==> Stopping and removing containers (volumes kept)"
    dc down
fi

echo "Done."
