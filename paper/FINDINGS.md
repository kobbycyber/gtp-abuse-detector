# Deployment Findings: Five Bugs Only the Live Path Exposed

This document is the detailed evidence log behind `PAPER.md` §8. The
project's offline path (`make test` + `make eval`) was correct and passing
*before any of this investigation started* — 7/7 unit tests, precision 1.0 /
recall 1.0 / F1 1.0 / FPR 0.0 on the labelled corpus. Bringing up the **live**
Docker lab for the first time (`make build && make lab-up && make attack`)
surfaced five real defects that the offline path structurally could not have
caught, because each one lives in code the offline path never executes:
container bring-up scripting, config-file rewriting, cross-stage Docker
`COPY` permissions, and the raw-socket send path.

Each finding below is written as: **symptom observed → root cause →
diagnosis method → fix → why the existing tests missed it**.

---

## Finding 1 — `core` image is missing `mongosh`; bring-up hangs forever with no error

**Symptom.** `docker compose up -d mongo core ran detector` returned
immediately and all containers showed `Up`, but `docker compose logs core`
stayed frozen on:

```
core-1  | [core] waiting for MongoDB at mongodb://mongo/open5gs ...
```

indefinitely — no error, no timeout, no crash loop. `docker compose ps`
showed everything green, actively misleading a health check that only looks
at container status.

**Root cause.** `core/entrypoint.sh` health-waits with:

```bash
until mongosh "${DB_URI}" --quiet --eval 'db.runCommand({ping:1}).ok' 2>/dev/null | grep -q 1; do
    sleep 1
done
```

and `open5gs-dbctl` (fetched raw from the upstream Open5GS repo in the same
Dockerfile) shells out to `mongosh` for every subscriber operation. But
`core/Dockerfile`'s apt install list —
`software-properties-common gnupg curl ca-certificates iproute2 iptables
iputils-ping tcpdump jq` plus the `open5gs` PPA package — never installs
`mongosh`. It isn't a transitive dependency of `open5gs` (that package links
against `libmongoc`, the C driver, not the Node-based shell), and it isn't in
Ubuntu's default repos at all — it ships from MongoDB's own APT repository.

**Diagnosis method.**

```bash
docker compose exec core which mongosh          # (empty)
docker compose exec core bash -c 'command -v mongosh; dpkg -l | grep -i mongo'
# ii  libmongoc-1.0-0   ...   MongoDB C client library
# ii  libmongocrypt0    ...   client-side field level encryption library
# (no mongosh)
```

`command -v mongosh` returning nothing inside a `set -euo pipefail` loop
whose every iteration is `... | grep -q 1` explains the silent infinite loop
exactly: `mongosh: command not found` on stderr is redirected to
`/dev/null`, the pipe's exit status is whatever `grep -q 1` returns (1, no
match), so the `until` just loops forever with a sleep, never surfacing the
real problem.

**Fix** (`core/Dockerfile`):

```diff
 RUN apt-get update && apt-get install -y --no-install-recommends \
         software-properties-common gnupg curl ca-certificates \
         iproute2 iptables iputils-ping tcpdump jq && \
     add-apt-repository -y ppa:open5gs/latest && \
-    apt-get update && apt-get install -y --no-install-recommends open5gs && \
+    curl -fsSL https://pgp.mongodb.com/server-7.0.asc | \
+        gpg --dearmor -o /usr/share/keyrings/mongodb-server-7.0.gpg && \
+    echo "deb [ arch=amd64 signed-by=/usr/share/keyrings/mongodb-server-7.0.gpg ] https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/7.0 multiverse" \
+        > /etc/apt/sources.list.d/mongodb-org-7.0.list && \
+    apt-get update && apt-get install -y --no-install-recommends \
+        open5gs mongodb-mongosh && \
     curl -fsSL https://raw.githubusercontent.com/open5gs/open5gs/main/misc/db/open5gs-dbctl \
         -o /usr/local/bin/open5gs-dbctl && chmod +x /usr/local/bin/open5gs-dbctl && \
     rm -rf /var/lib/apt/lists/*
```

Pinned to the `mongodb-org/7.0` channel, matching the `mongo:7` image already
used by `docker-compose.yml`, so client/server major versions stay aligned.

**Why the offline path never caught this.** `mongosh` is invoked nowhere in
`detector/`, `attacker/`, or `eval/` — it is exclusively a live-core
bring-up concern. `make test` and `make eval` never touch Docker at all.

---

## Finding 2 — the NGAP/GTP-U bind-address patch silently no-ops, but *logs success anyway*

**Symptom.** After fixing Finding 1, `core` fully started (all NFs
launched, subscriber registered), but `ran`'s gNB could never complete NGAP:

```
ran-1  | [sctp] [info] Trying to establish SCTP connection... (10.10.10.10:38412)
ran-1  | [sctp] [error] Connecting to 10.10.10.10:38412 failed. SCTP could not connect: Connection refused
```

repeating on every gNB restart, even minutes after `core` had been up and
healthy. Yet `core`'s own log clearly printed:

```
core-1  | [core] bound NGAP+GTP-U to 10.10.10.10 (PLMN 999/70 TAC 1)
```

— a confident, specific, *wrong* success message.

**Root cause.** `entrypoint.sh` patches the packaged Open5GS YAML configs
with a small inline Python script using regex substitution:

```python
patch("/etc/open5gs/amf.yaml", [
    (r"(ngap:\s*\n(?:.*\n)*?\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
])
```

The actual packaged `amf.yaml` contains:

```yaml
  ngap:
    server:
      - address: 127.0.0.5
```

The regex's `\s*address:\s*` segment requires the token `address:` to be
preceded only by whitespace. But in the real file it's preceded by `- `
(YAML list-item dash + space) — `-` is not a whitespace character, so the
pattern never matches. `re.sub()` on a zero-match pattern is not an error in
Python: it silently returns the input string unchanged. The `print(...)`
line announcing success ran unconditionally, regardless of whether either
`patch()` call actually replaced anything. Confirmed identically broken for
`upf.yaml`'s `gtpu.server[0].address`.

**Diagnosis method.**

```bash
docker compose exec core cat /etc/open5gs/amf.yaml | grep -A2 'ngap:'
#   ngap:
#     server:
#       - address: 127.0.0.5      <-- still loopback, never rebound

docker compose exec core bash -c "ss -lnp --sctp"
# LISTEN 0 5  127.0.0.5:38412  0.0.0.0:*  users:(("open5gs-amfd",...))
#            ^^^^^^^^^^ bound to internal loopback, unreachable from the ran container
```

**Fix** (`core/entrypoint.sh`): match the optional list-item dash
explicitly, and make the patch helper *warn instead of lie* when a pattern
doesn't match:

```diff
 def patch(path, repls):
     try:
         s = open(path).read()
     except FileNotFoundError:
         return
     for pat, rep in repls:
-        s = re.sub(pat, rep, s)
+        s, n = re.subn(pat, rep, s)
+        if n == 0:
+            print(f"[core] WARNING: pattern did not match in {path}: {pat}")
     open(path, "w").write(s)

 patch("/etc/open5gs/amf.yaml", [
-    (r"(ngap:\s*\n(?:.*\n)*?\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
+    (r"(ngap:\s*\n(?:.*\n)*?\s*-\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
 ])
 patch("/etc/open5gs/upf.yaml", [
-    (r"(gtpu:\s*\n(?:.*\n)*?\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
+    (r"(gtpu:\s*\n(?:.*\n)*?\s*-\s*address:\s*)[0-9.]+", r"\g<1>"+core_ip),
 ])
```

Verified post-fix:

```bash
docker compose exec core bash -c "ss -lnp --sctp"
# LISTEN 0 5  10.10.10.10:38412  0.0.0.0:*  users:(("open5gs-amfd",...))
```

**Why the offline path never caught this.** This regex only runs inside the
`core` container's entrypoint at Docker-container boot; there is no unit
test or offline-eval code path that renders `amf.yaml`/`upf.yaml` at all.

**Broader pattern.** This bug and Finding 4 below share the same shape as
the project's own headline R1 finding (`docs/ARCHITECTURE.md`): code that
*looks* like it does the right thing, produces a reassuring log line, and
passes every check that operates purely in-memory or on constructed
objects — but silently does nothing once real bytes (a real YAML file, a
real Ethernet frame) are involved. Passive/wire-level tooling seems
unusually prone to this failure class; see `PAPER.md` §8 for the general
lesson.

---

## Finding 3 — `nr-binder` loses its executable bit across the multi-stage Docker build

**Symptom.**

```bash
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
# OCI runtime exec failed: exec failed: unable to start container process:
# exec: "./build/nr-binder": permission denied
```

**Root cause.** `ran/Dockerfile` is a two-stage build: UERANSIM is compiled
from source in a `build` stage, then only `/src/build/` is copied into the
slim final image with `COPY --from=build /src/build/ ./build/`. `nr-binder`
is a plain shell-script wrapper (not a compiled binary — it sets
`LD_PRELOAD=./libdevbnd.so UE_BIND_ADDR=$addr` for namespace-binding
tricks), and it ended up in the build stage's output directory without the
executable bit set (`-rw-r--r--`, confirmed via `docker compose exec ran
ls -la build/`). The `chmod +x` in the Dockerfile only covered `/run.sh`.

**Fix** (`ran/Dockerfile`):

```diff
 COPY run.sh /run.sh
-RUN chmod +x /run.sh
+RUN chmod +x /run.sh ./build/nr-binder
```

**Why the offline path never caught this.** `nr-binder` is a live-RAN
convenience tool for running a command bound to the UE's tunnel address from
inside the container; nothing in `detector/`, `attacker/`, or `eval/`
touches it.

---

## Finding 4 — the attacker's `--send` path emits malformed Ethernet frames (highest-severity finding)

**Symptom.** After Findings 1–3 were fixed and the live core/RAN were fully
healthy (confirmed NG Setup, PDU session, working ping through the tunnel),
firing `make attack` produced **zero** detector output — not even a
false-negative pattern, literally zero packets counted:

```json
{"packets_seen": 0, "gtpu_packets": 0, "rule_hits": {}, "latency": {"count": 0}}
```

**Root cause.** `attacker/generate_attacks.py` builds every packet rooted at
`IP(...)` — e.g. `outer(dst, teid, sport_ip)` returns
`IP(src=..., dst=...) / UDP(...) / GTP_U_Header(...)` — with **no `Ether()`
layer**. The `--send` code path called Scapy's `sendp()`:

```python
from scapy.all import sendp
sendp(pkts, iface=args.iface, verbose=False)
```

`sendp()` sends at Layer 2: it opens a raw `AF_PACKET` socket and writes
`bytes(pkt)` directly onto the wire, assuming the packet *already contains* a
valid 14-byte Ethernet header. Since these packets start at IP, Scapy has no
Ethernet header to write — it serializes the IP packet as-is, and the first
14 bytes of that (which happen to be the IP version/IHL/ToS/length/id/flags
fields) get interpreted by the network stack and any listener as a bogus
Ethernet destination MAC + source MAC + ethertype.

**Diagnosis method.** tcpdump inside the shared core network namespace, with
no BPF filter at all, capturing while firing a single attack packet:

```bash
docker compose exec -d core tcpdump -i eth0 -n -c 20 -w /tmp/test2.pcap
docker compose run --rm attacker --class gtp_in_gtp --send --iface eth0 \
    --upf 10.10.10.10 --gnb 10.10.10.20
docker compose exec core tcpdump -r /tmp/test2.pcap -n
```

```
15:32:53.791521 00:00:40:11:52:73 > 45:00:00:48:00:01, ethertype Unknown (0x0a0a), length 72:
        0x0000:  0a14 0a0a 0a0a 0868 0868 0034 6543 3000  .......h.h.4eC0.
        ...
```

`45:00:00:48:00:01` as a *destination MAC address* is the unmistakable
signature: `0x45` is IPv4's version/IHL byte, `0x00` is ToS, `0x0048` is
total length (72) — i.e. that's the start of the IP header being read back
as a MAC address by tcpdump's Ethernet decoder. `ethertype Unknown (0x0a0a)`
confirms the "ethertype" field tcpdump extracted is also just IP-header
bytes, not a real `0x0800`. This is not a filter/timing issue — the frame on
the wire is structurally invalid Ethernet.

**Fix** (`attacker/generate_attacks.py`, both the single-packet and
corpus-send paths):

```diff
         if args.send:
-            from scapy.all import sendp
-            sendp(pkt, iface=args.iface, verbose=True)
+            from scapy.all import send
+            # These packets are built IP-rooted (no Ether layer), so they
+            # must go out at L3: send() lets the kernel add a real Ethernet
+            # header and resolve ARP. sendp() would write the IP bytes
+            # straight onto the wire as if they were already a frame.
+            send(pkt, iface=args.iface, verbose=True)
```

```diff
     if args.send:
-        from scapy.all import sendp
+        from scapy.all import send
         print(f"[!] sending {len(pkts)} packets on {args.iface} (lab bridge)")
-        sendp(pkts, iface=args.iface, verbose=False)
+        send(pkts, iface=args.iface, verbose=False)
```

`send()` operates at Layer 3: it hands the IP packet to the kernel's routing
+ ARP machinery, which builds a real Ethernet header (resolving the next-hop
MAC, or falling back to broadcast for unreachable synthetic destinations
like `8.8.8.8`, which is expected and harmless here since the detector's raw
socket sees all frames on the shared namespace regardless of destination
MAC).

Post-fix verification, same tcpdump technique, single packet:

```
15:32:55.340526 IP 10.10.10.10.38412 > 10.10.10.20.37689: sctp ...
```
— real, correctly-framed IP/UDP traffic, and the detector immediately began
emitting findings on the next full corpus run (131 findings across all four
rule classes on a 500-packet live run; see `RESULTS.md` §4).

**Why the offline path never caught this — and why this is the most
consequential finding.** Every automated check in this repository that
touches `generate_attacks.py` uses `wrpcap()` / `PcapReader()`, never
`sendp()`/`send()`:

- `detector/tests/test_rules.py` builds packets in-memory and calls
  `evaluate()` directly — no serialization at all.
- `eval/run_eval.py` calls `generate_attacks.py --write ... --labels-out ...`
  — the `--write` path, not `--send`.
- `make eval`'s reference numbers (precision 1.0 / recall 1.0 / F1 1.0) are
  entirely produced through `wrpcap`/`PcapReader`, which round-trip packets
  through Scapy's *own* dissector, not through a live L2 socket — so a
  missing Ethernet header is structurally invisible to that path.

The `--send` code path exists specifically for live-fire demonstrations
(`make attack`, and the `README.md`/`docs/LAB_GUIDE.md` "Fire abuse and
watch detections" instructions) — the one thing a reader is most likely to
actually try after cloning the repo — and it was broken from first commit
through every offline-verified state of the codebase. **A 100% F1 score on
the reproducible offline corpus said nothing about whether the live demo
path worked at all**, because the two paths shared the detection *rules*
but not the packet *transmission* code.

---

## Finding 5 — `network_mode: service:core` silently orphans dependents on `core` recreation

**Symptom.** After rebuilding and recreating `core` to apply Findings 1 and
2, `detector`'s logs went from actively processing traffic to permanently
frozen:

```
detector-1  | WARNING: Socket <scapy.arch.linux.L2ListenSocket object at ...> failed with '[Errno 100] Network is down'. It was closed.
```

with no further output, and `docker compose restart detector` did **not**
fix it — it failed outright:

```
Error response from daemon: Cannot restart container ...: joining network
namespace of container: No such container: a1d8c8c3...
```

**Root cause.** `docker-compose.yml` attaches both `detector` and `attacker`
to `network_mode: "service:core"` — by design, so the detector taps the
UPF's actual interface rather than a mirrored/switched copy (see
`docs/ARCHITECTURE.md`). But this binds to a *specific container instance*'s
network namespace, identified by container ID, at the moment `detector`
itself starts. `docker compose up -d core` after an image rebuild does not
edit the running `core` container in place — it stops the old one, removes
it, and creates a new one with a new container ID and a new network
namespace. Every dependent still pointing at the old namespace is now
attached to nothing.

**Diagnosis method.** Straightforward once the error message is read
carefully — `docker compose restart` names the now-deleted container ID
explicitly. The non-obvious part is that `docker compose ps` shows
`detector` as `Up` throughout, giving no visual signal that it is
effectively dead.

**Fix (operational, not code).** `docker compose restart` cannot repair
this — the container must be recreated, not restarted, so it re-resolves
`network_mode: service:core` against the *current* `core` container:

```bash
docker compose up -d --force-recreate detector
```

`ran` needs the same treatment whenever its own NGAP handshake raced
`core`'s AMF coming up before the fix — not because of the netns-sharing
issue (RAN has its own dedicated network), but because UERANSIM's `run.sh`
attempts NG Setup exactly once at container start and does not retry a
refused SCTP connection:

```bash
docker compose restart ran
```

This is documented as an explicit step in `REPRODUCE.md` §B.5, and is worth
upstreaming as either a `make redeploy` convenience target or a documented
runbook step — it is not currently automated anywhere in this repo.

**Why the offline path never caught this.** `network_mode` is exclusively a
Docker Compose live-deployment concept; nothing offline exercises container
networking at all.

---

## Summary table

| # | Component | Symptom | Root cause | Severity |
|---|---|---|---|---|
| 1 | `core/Dockerfile` | Bring-up hangs forever, no error | `mongosh` never installed | High — total live-path bring-up failure |
| 2 | `core/entrypoint.sh` | AMF/UPF unreachable from `ran`, but core logs claim success | Regex didn't match YAML `- address:` list syntax; `re.sub` no-ops silently | High — silent, self-reported false success |
| 3 | `ran/Dockerfile` | `nr-binder` permission denied | Exec bit lost across multi-stage `COPY --from` | Low — affects one optional debug helper |
| 4 | `attacker/generate_attacks.py` | Zero packets ever reach the detector on `--send` | `sendp()` used on `Ether()`-less packets; malformed frames | **Critical — every live attack demo was broken from day one** |
| 5 | `docker-compose.yml` design | Detector/RAN silently stop working after any `core` rebuild | `network_mode: service:core` binds to a container ID, not a service name, at attach time | Medium — recurring operational trap during iteration |

All five are now fixed in the working tree (Findings 1–4 as code changes;
Finding 5 as a documented operational procedure in `REPRODUCE.md`). None of
the five were reachable from `make test` or `make eval` — see `PAPER.md` §8
for the methodological lesson this suggests about validating passive
network-security tooling.
