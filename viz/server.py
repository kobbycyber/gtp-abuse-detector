#!/usr/bin/env python3
"""
viz/server.py -- live dashboard backend for the gtpu-abuse-lab passive detector.

Tails the detector container's own --json stdout (already wired in
docker-compose.yml) and re-publishes each JSON line to any number of
connected browsers over Server-Sent Events. No new Docker service, no new
Python dependency -- this runs on the host with the standard library only.

Uses `docker logs -f <container-id>`, NOT `docker compose logs -f detector`:
the latter buffers its output when stdout isn't a TTY (its log multiplexer
holds lines back for formatting), so lines can sit unflushed for a long time,
or indefinitely when wrapped through `sg docker` with no controlling
terminal at all -- plain `docker logs -f` streams promptly in both cases.
The container ID is resolved once per (re)connect via `docker compose ps -q`.

Usage:
    python3 viz/server.py [--port 8090]

Then open http://localhost:8090 while the lab is up (scripts/lab_up.sh).
If the lab isn't up yet, the dashboard loads fine and just shows a
"waiting for detector..." state until the detector container appears --
resolution and tailing are both retried in a loop rather than failing.
"""
from __future__ import annotations

import argparse
import json
import queue
import shlex
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parent
INDEX_HTML = ROOT / "index.html"

clients: list[queue.Queue] = []
clients_lock = threading.Lock()


def broadcast(event: dict) -> None:
    payload = json.dumps(event)
    with clients_lock:
        dead = []
        for q in clients:
            try:
                q.put_nowait(payload)
            except queue.Full:
                dead.append(q)
        for q in dead:
            clients.remove(q)


_in_docker_group_cache: bool | None = None


def _in_docker_group() -> bool:
    """Cached: can we talk to the Docker socket directly? If not, every
    call is wrapped through `sg docker` instead -- the same situation
    scripts/lab_up.sh handles (see paper/REPRODUCE.md B.1)."""
    global _in_docker_group_cache
    if _in_docker_group_cache is None:
        try:
            subprocess.run(["docker", "info"], stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL, check=True, timeout=5)
            _in_docker_group_cache = True
        except Exception:
            _in_docker_group_cache = False
    return _in_docker_group_cache


def _wrap(cmd: list[str]) -> list[str]:
    if _in_docker_group():
        return cmd
    quoted = " ".join(shlex.quote(part) for part in cmd)
    return ["sg", "docker", "-c", quoted]


def _resolve_container_id() -> str | None:
    try:
        out = subprocess.run(
            _wrap(["docker", "compose", "ps", "-q", "detector"]),
            cwd=str(ROOT.parent), capture_output=True, text=True,
            timeout=10, check=True,
        )
        cid = out.stdout.strip()
        return cid or None
    except Exception:
        return None


def tail_detector() -> None:
    """Follow the detector's JSON log lines forever. Retries if the lab
    isn't up yet, the detector container gets recreated, or the stream
    ends."""
    while True:
        cid = _resolve_container_id()
        if not cid:
            time.sleep(3)
            continue
        cmd = _wrap(["docker", "logs", "-f", "--tail", "0", cid])
        try:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, bufsize=1,
            )
            assert proc.stdout is not None
            for line in proc.stdout:
                line = line.strip()
                if not line.startswith("{"):
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                event.setdefault("type", "finding" if "rule" in event else "unknown")
                broadcast(event)
            proc.wait()
        except FileNotFoundError:
            pass  # docker itself not on PATH -- keep retrying quietly
        time.sleep(3)


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):
        pass  # keep the terminal quiet; this is a long-lived SSE server

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self._serve_index()
        elif self.path == "/events":
            self._serve_events()
        else:
            self.send_response(404)
            self.end_headers()

    def _serve_index(self):
        body = INDEX_HTML.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _serve_events(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        q: queue.Queue = queue.Queue(maxsize=1000)
        with clients_lock:
            clients.append(q)
        try:
            while True:
                payload = q.get()
                self.wfile.write(f"data: {payload}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with clients_lock:
                if q in clients:
                    clients.remove(q)


def main():
    p = argparse.ArgumentParser(description="Live dashboard for the gtpu-abuse-lab detector")
    p.add_argument("--port", type=int, default=8090)
    args = p.parse_args()

    threading.Thread(target=tail_detector, daemon=True).start()

    httpd = ThreadingHTTPServer(("0.0.0.0", args.port), Handler)
    print(f"[*] Dashboard: http://localhost:{args.port}  (Ctrl-C to stop)", file=sys.stderr)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
