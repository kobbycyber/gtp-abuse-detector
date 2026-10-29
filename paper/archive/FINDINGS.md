# Deployment Findings: Seven Defects Only the Live Path Exposed

This document is the detailed evidence log behind `PAPER.md` §8. The
project's offline path (`make test` + `make eval`) was passing *before any
of this investigation started* (Finding 7 later showed that one rule it
exercised was wrong on an input it never generated) — 7/7 unit tests, precision 1.0 /
recall 1.0 / F1 1.0 / FPR 0.0 on the labelled corpus. Bringing up the **live**
Docker lab for the first time (`make build && make lab-up && make attack`)
surfaced five real defects that the offline path structurally could not have
caught, because each one lives in code the offline path never executes:
container bring-up scripting, config-file rewriting, cross-stage Docker
`COPY` permissions, and the raw-socket send path.

Two more defects (Findings 6 and 7) were found later, during revision, by a
labelled live run: the corpus that `make attack` sends, scored packet by
packet against its labels. At that point the offline path again passed in
full (21/21 unit tests, precision, recall and F1 1.0). Finding 6 lives in
container bring-up scripting and in the check the docs gave for proving the
UE data path. Finding 7 is the only one in detection logic. The offline path
does execute that code, but its corpus never produces the packet sequence
that triggers it.

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

**Later correction.** With the exec bit fixed, the `nr-binder` ping ran and
got replies, but it never used the tunnel. `nr-binder` preloads
`./libdevbnd.so` by a relative path, and run from `/ueransim` as documented
the loader cannot find it, so `ping` ran unbound. Finding 6 covers this. The documented check is now
`docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8`.

---

## Finding 4 — the attacker's `--send` path emits malformed Ethernet frames (highest-severity finding)

**Symptom.** After Findings 1–3 were fixed and the live core/RAN were fully
healthy (confirmed NG Setup and PDU session; the `nr-binder` ping also got
replies, though Finding 6 later showed that ping never used the tunnel),
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

`send()` operates at Layer 3: Scapy looks up the route and the next-hop MAC
and builds a real Ethernet header in front of the IP packet. In the lab the
outer destination is the UPF at 10.10.10.10, which is the core's own
address, and the attacker sends from inside the core's network namespace.
Scapy cannot resolve a MAC for that address, prints `MAC address to reach
destination not found. Using broadcast.`, and sends every frame as a
broadcast. This is expected and harmless, since the detector sniffs `eth0`
in the same namespace and sees the frames whatever their destination MAC.
It does make the send slow: Scapy tries the lookup for each packet before
falling back, so a 500-packet run takes about 17 minutes.

Post-fix, the detector began emitting findings on the next full corpus
run, across all four rule classes; on a fresh lab it saw all 500 of 500
packets (below).

An earlier version of this document gave 131 findings for that 500-packet
live run (R1 22, R2 17, R3 37, R4 55). That figure did not reproduce and is
withdrawn. On a fresh lab the same corpus (seed 1337, 400 malicious and 100
benign packets) was seen in full by the detector, 500 of 500 packets, and
raised 608 findings with the R2 code of the time: R1 82, R2 146, R3 150,
R4 230. After the Finding 7 fix a live run of the same corpus gave 550:
R1 82, R2 88, R3 150, R4 230. Findings exceed the 400 malicious packets
because rules overlap: every PFCP and NGAP smuggling packet raises both R3
and R4, since its inner destination is the UPF (400 + 150 = 550). In the 608
figure the remaining 58 findings are extra R2 hits (146 against 88) caused
by the Finding 7 defect. See `RESULTS.md` §4.

**Why the offline path never caught this — and why this is the most
consequential finding.** Every automated check in this repository that
touches `generate_attacks.py` either round-trips packets in process with
`bytes()` or writes them with `wrpcap()`, never `sendp()`/`send()`:

- `detector/tests/test_rules.py` builds packets in-memory and calls
  `evaluate()` directly. At the time it did no serialization at all; tests
  added since serialize with `bytes()`, but none of them sends a packet.
- `eval/run_eval.py` runs `eval/benchmark.py`, which imports the
  `generate_attacks.py` builders and round-trips every packet through
  `bytes()` and `IP()` in process; `--write-pcap` only saves a copy with
  `wrpcap()`. Neither path touches `--send`.
- `make eval`'s reference numbers (precision 1.0 / recall 1.0 / F1 1.0) are
  produced by that in-process `bytes()` round trip through Scapy's *own*
  dissector, not through a live L2 socket, so a missing Ethernet header is
  structurally invisible to that path.

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

This is documented as an explicit step in `REPRODUCE.md` §B.5.
`scripts/lab_up.sh` performs both steps on a full bring-up: it restarts
`ran` once if its first NG Setup was refused, and force-recreates `detector`
after `core` is up. `make lab-up` does not call that script and there is no
`make redeploy` target, so after a manual `core` rebuild the two commands
above are still needed.

**Why the offline path never caught this.** `network_mode` is exclusively a
Docker Compose live-deployment concept; nothing offline exercises container
networking at all.

---

## Finding 6 — no UE packet ever reached the data network, and the documented ping check hid it

**Symptom.** Nothing looked wrong. The check the docs gave for proving N3
carried real user-plane traffic,

```bash
docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
```

returned replies. The fault surfaced during revision, with the labelled live
run: the UPF logged `ogs_tun_write() failed` for every uplink GTP-U packet
it decapsulated, so no UE packet ever reached the data network.

**Root cause.** Two faults, one hiding the other.

1. Nothing in the container configured the UPF's TUN device. The Open5GS
   UPF writes each decapsulated uplink packet to `ogstun`. Outside a
   container the packaged systemd-networkd unit gives that device its
   address and brings it up. In `core` nothing did: `ogstun` had no address
   and its link was down, and there was no NAT rule to carry the UE pool
   (10.45.0.0/16) out of `eth0`. Every write to the device failed.
2. The check could not see this. `nr-binder` works by setting
   `LD_PRELOAD=./libdevbnd.so` (Finding 3) so that the wrapped program's
   sockets bind to the UE address. The path is relative to the current
   directory, and the documented command runs from `/ueransim`, while the
   library lives in `/ueransim/build/`. The loader cannot find it, prints
   `ERROR: ld.so: object './libdevbnd.so' from LD_PRELOAD cannot be
   preloaded (cannot open shared object file): ignored.` above the ping
   output, and runs `ping` without it. The ping therefore ran unbound, followed
   Docker's default route out of `ran`'s `eth0` with source 10.10.10.20,
   and its replies came back the same way. It never entered `uesimtun0` or
   the tunnel.

**Diagnosis method.** Packet captures on both sides during the old check.
Inside `ran`, the echo request leaves `eth0` from the gNB's address as
plain ICMP, not as GTP-U:

```
09:49:32.221483 eth0  Out IP 10.10.10.20 > 8.8.8.8: ICMP echo request, id 3, seq 1, length 64
09:49:32.235785 eth0  In  IP 8.8.8.8 > 10.10.10.20: ICMP echo reply, id 3, seq 1, length 64
```

A capture on the core over the same ping saw zero GTP-U packets. Run as
documented, the command also prints the loader's error before the ping
output:

```
ERROR: ld.so: object './libdevbnd.so' from LD_PRELOAD cannot be preloaded (cannot open shared object file): ignored.
```

**Fix** (`core/entrypoint.sh`): give `ogstun` the UE-pool gateway address,
bring it up, and NAT the pool out of `eth0`. The NAT rule is added only if
it is not already present, so a container restart does not duplicate it.

```diff
+# --- UE data path: give the UPF's TUN device the UE-pool gateway address and
+# NAT the pool out of eth0. Outside a container the packaged systemd-networkd
+# unit does this; here nothing does, and without it the UPF decapsulates
+# uplink GTP-U and then fails ogs_tun_write(), so no UE packet reaches the
+# data network and no reply comes back.
+UE_SUBNET="${UE_SUBNET:-10.45.0.0/16}"
+UE_GW="${UE_GW:-10.45.0.1/16}"
+ip tuntap add name ogstun mode tun 2>/dev/null || true
+ip addr replace "${UE_GW}" dev ogstun
+ip link set ogstun up
+iptables -t nat -C POSTROUTING -s "${UE_SUBNET}" ! -o ogstun -j MASQUERADE 2>/dev/null || \
+    iptables -t nat -A POSTROUTING -s "${UE_SUBNET}" ! -o ogstun -j MASQUERADE
+echo "[core] ogstun ${UE_GW} up, NAT for ${UE_SUBNET}"
```

The documented check now binds the ping to the UE's tunnel interface
directly, which needs no preload:

```diff
-docker compose exec ran ./build/nr-binder 10.45.0.2 ping -c3 8.8.8.8
+docker compose exec ran ping -I uesimtun0 -c3 8.8.8.8
```

**Verified post-fix.** A capture on the core during the new check shows the
whole path: uplink GTP-U from the gNB, the inner packet on `ogstun`, NAT out
of `eth0`, the reply back through `ogstun`, and downlink GTP-U to the gNB.

```
09:54:07.107991 eth0  In  IP 10.10.10.20.2152 > 10.10.10.10.2152: UDP, length 100
09:54:07.111272 ogstun In  IP 10.45.0.2 > 8.8.8.8: ICMP echo request, id 5, seq 1, length 64
09:54:07.111321 eth0  Out IP 10.10.10.10 > 8.8.8.8: ICMP echo request, id 5, seq 1, length 64
09:54:07.124747 eth0  In  IP 8.8.8.8 > 10.10.10.10: ICMP echo reply, id 5, seq 1, length 64
09:54:07.124767 ogstun Out IP 8.8.8.8 > 10.45.0.2: ICMP echo reply, id 5, seq 1, length 64
...
09:54:07.125138 eth0  Out IP 10.10.10.10.2152 > 10.10.10.20.2152: UDP, length 100
```

All 3 replies were received. The detector counted the packets and raised
zero findings. The session's real TEIDs in this run were 0xb2aa uplink (gNB
to UPF) and 0x1 downlink (UPF to gNB). Replies marked `(DUP!)` can appear.
They come from the host's own network, which delivers each reply to the
core's `eth0` several times, and not from the lab.

**Why the offline path never caught this.** `core/entrypoint.sh` runs only
when the `core` container starts, and `make test` and `make eval` never
start a container. The live check meant to cover that gap passed for a
reason unrelated to the tunnel: it only needed the host to reach 8.8.8.8.
This is the same shape as Finding 2, a check that reports success while the
thing it is meant to check does nothing. The live detection results were
not affected, because the attacker is not a UE and does not use this path:
it writes crafted GTP-U with a raw socket straight onto the core's `eth0`.

---

## Finding 7 — R2 handed a TEID to whichever source sent last, and keyed it on the TEID alone

**Symptom.** The labelled live run scores the exact corpus `make attack`
sends (seed 1337, 400 malicious and 100 benign packets) against its labels.
Every packet in it uses TEID 0x1 and outer destination 10.10.10.10 (the
UPF). Every packet comes from the gNB address 10.10.10.20, except the
`teid_spoof` packets, which come from 10.10.10.66. The composition is
benign 100, `teid_spoof` 88, `gtp_in_gtp` 82, `inner_to_core` 80,
`pfcp_smuggle` 79 and `ngap_smuggle` 71. With the detector configured as in
`docker-compose.yml` (gNB allowlist 10.10.10.20 and 10.10.10.21), it scored
TP 385, FP 16, FN 15, TN 84: precision 0.960, recall 0.9625, F1 0.961, FPR
0.16. The offline benchmark, run on the same code, scored precision, recall
and F1 of 1.0 with FPR 0.0. All 16 false positives were a benign packet
immediately after a `teid_spoof`. All 15 false negatives were a
`teid_spoof` immediately after another `teid_spoof`.

**Root cause.** Two faults in `rule_teid_spoof()` in `detector/rules.py`,
both copied into the naive baseline in `detector/baselines.py`.

1. Last source wins. On any change of source the old code moved ownership
   to the new source before deciding whether to alert (the comment read
   "Track the latest owner either way"). The first spoof from 10.10.10.66
   was flagged, but the rogue became the owner. The gNB's next packet then
   looked like a change of source and was flagged: a false positive on a
   benign packet. A second spoof straight after the first matched the new
   owner and raised nothing: a false negative.
2. The key was the TEID alone. A TEID is unique only within the endpoint
   that receives it (TS 29.281), so the same number on the UPF's uplink and
   on a gNB's downlink names two different tunnels. In this lab the real
   session used downlink TEID 0x1 (UPF to gNB), and the attack corpus sends
   to the UPF on TEID 0x1. With a TEID-only key, downlink traffic from the
   UPF and uplink traffic to the UPF would share one owner entry. This
   fault caused none of the errors above, since all of them are explained
   by the first fault, but it would misfire whenever UE traffic and the
   corpus run together.

**Diagnosis method.** Two checks ruled out the live path itself. The
detector saw 500 of 500 packets, so nothing was lost in capture. The live
findings stream was identical, in order and content (rule, source,
destination, TEID, detail), to an offline `gtpu_detector.py pcap` pass over
the same corpus written to a file, for all 608 findings of the run. The
errors therefore come from the rule, and they reproduce offline on the same
packet sequence. Lining the per-packet verdicts up against the labels then
showed the pattern above: every error sat directly after a spoof. The
offline reproduction is now a Makefile target, `make live-score`, which
runs:

```bash
python3 attacker/generate_attacks.py --count 400 --benign 100 --upf 10.10.10.10 \
    --smf 10.10.10.11 --gnb 10.10.10.20 \
    --write captures/live_corpus.pcap --labels-out captures/live_corpus.labels.json
python3 detector/gtpu_detector.py pcap --file captures/live_corpus.pcap \
    --labels captures/live_corpus.labels.json \
    --core-ips 10.10.10.10,10.10.10.11 --gnb-ips 10.10.10.20,10.10.10.21 \
    --metrics-out captures/live_corpus.metrics.json
```

**Fix** (`detector/rules.py`; the same change in `naive_teid_spoof()` in
`detector/baselines.py`): key ownership on (receiving address, TEID), where
the receiving address is the destination of the outer header that carries
the tunnel, let the first source win, and let only an allowlisted gNB take
ownership.

```diff
+def outer_net(pkt: Packet):
+    """The IPv4 or IPv6 header that carries the outer GTP-U datagram, or None.
+
+    pkt[IP] would return the first IPv4 layer anywhere in the packet, which
+    over IPv6 N3 transport is the subscriber's inner packet, not the tunnel's.
+    """
+    udp = pkt[GTP_U_Header].underlayer
+    net = udp.underlayer if udp is not None else None
+    return net if isinstance(net, (IP, IPv6)) else None
+
+
 def rule_teid_spoof(pkt: Packet, state: DetectorState) -> list[Finding]:
     """R2: a TEID previously seen from IP A now arrives from IP B."""
-    if not pkt.haslayer(GTP_U_Header) or not pkt.haslayer(IP):
+    if not pkt.haslayer(GTP_U_Header):
+        return []
+    net = outer_net(pkt)
+    if net is None:
         return []
     teid = int(pkt[GTP_U_Header].teid)
-    src = pkt[IP].src
-    owner = state.teid_owner.get(teid)
+    src, dst = net.src, net.dst
+    # A TEID is unique only within the endpoint that receives it (TS 29.281),
+    # so ownership is keyed on (receiving address, TEID). Keying on the TEID
+    # alone conflated a UPF's uplink tunnel with a gNB's downlink tunnel that
+    # happened to carry the same number.
+    key = (dst, teid)
+    owner = state.teid_owner.get(key)
     if owner is None:
-        state.teid_owner[teid] = src
+        state.teid_owner[key] = src
         return []
     if owner != src:
-        # Suppress legitimate handovers: if an allowlist of gNB IPs is
-        # configured and BOTH the old and new source are known gNBs, this is a
-        # normal Xn/N2 handover, not a spoof. Track the latest owner either way.
-        state.teid_owner[teid] = src
-        if state.known_gnb_ips and state.is_known_gnb(src) and state.is_known_gnb(owner):
+        # With the allowlist configured, a known gNB always takes ownership
+        # and stays silent: that covers a legitimate Xn/N2 handover, and the
+        # legitimate gNB reclaiming a tunnel a rogue happened to be seen on
+        # first (for example after a detector restart).
+        if state.known_gnb_ips and state.is_known_gnb(src):
+            state.teid_owner[key] = src
             return []
+        # Anything else is a conflict. Ownership is NOT transferred (first
+        # source wins), so a rogue cannot take the TEID over. Transferring it
+        # made the legitimate owner's next packet look like the spoof and hid a
+        # repeated spoof from the same rogue; the live corpus, where spoofs and
+        # legitimate packets interleave on one TEID, exposed both.
         return [Finding(
             rule="R2_TEID_SPOOF", severity="high",
-            src=src, dst=pkt[IP].dst, teid=teid,
+            src=src, dst=dst, teid=teid,
             detail=f"TEID {hex(teid)} first bound to {owner}, now sourced from {src}.",
         )]
```

A packet whose source differs from the owner now raises R2 and leaves
ownership where it was. The one exception is the gNB allowlist (`--gnb-
ips`): when it is configured, an allowlisted gNB always takes ownership with
no finding. That covers a handover, and it lets the real gNB reclaim a
tunnel a rogue was seen on first, for example after a detector restart;
without it the rogue would keep the tunnel and the gNB would be flagged on
every packet. Ownership is read from the outer IPv4 or IPv6 header that
carries the tunnel, not from `pkt[IP]`, which over IPv6 transport would be
the subscriber's inner packet. Without the allowlist every
change is flagged and ownership never moves, so a handed-over session keeps
alerting for as long as it sends from the new gNB. Under the old code the
same handover raised a single alert, because ownership moved with it.

**Verified post-fix.**

- `make test` gives 24 passed, up from 21. Three tests are new:
  `test_teid_spoof_rogue_cannot_take_ownership` (spoofs interleaved with the
  owner's packets on one TEID, and an allowlisted gNB reclaiming a tunnel a
  rogue was seen on first), `test_teid_scoped_by_receiving_endpoint` (uplink
  and downlink on the same TEID number, and ownership read from the outer
  header over IPv6 transport) and
  `test_live_attack_corpus_scores_clean` (the exact `make attack` corpus
  must score with no false positive and no false negative).
  `test_naive_and_robust_agree_on_non_reparse_rules` in `test_baseline.py`
  now also checks R2 on interleaved spoofs for both the detector and the
  naive baseline. All four fail on the old R2 code and pass on the new.
- The offline benchmark, rerun with seeds 1337, 1, 2, 3 and 4, gives all
  132 non-timing metrics identical to before the fix.
- The same live corpus, scored per packet with the commands above
  (`make live-score`), before and after the fix:

| | Findings (R1 / R2 / R3 / R4) | TP | FP | FN | TN | Precision | Recall | F1 | FPR |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Before the fix | 608 (82 / 146 / 150 / 230) | 385 | 16 | 15 | 84 | 0.960 | 0.9625 | 0.961 | 0.16 |
| After the fix | 550 (82 / 88 / 150 / 230) | 400 | 0 | 0 | 100 | 1.0 | 1.0 | 1.0 | 0.0 |

R2 now fires exactly once for each of the 88 `teid_spoof` packets. R1, R3
and R4 are unchanged.

- The fix was also confirmed in the live lab. Four real UE pings through the
  tunnel before the attack (20 GTP-U packets) raised no finding. The
  500-packet `make attack` run was seen in full, 500 of 500 packets, and
  raised 550 findings (R1 82, R2 88, R3 150, R4 230), identical in order and
  content to the offline pass. Four more pings afterwards (20 packets) raised
  no new finding, and the detector's `packets_seen` ended at 540 (500 + 40).
  The pings exercise the receiver-scoped key on the real session: its
  downlink TEID was 0x1, the TEID the attack corpus sends to the UPF.

**Why the offline path never caught this.** Unlike Findings 1 to 6, this
code runs under both `make test` and `make eval`. The offline inputs never
produced the triggering sequence. The benchmark corpus gives every spoof its
own victim TEID, emits all the victims first, and has a single receiver, so
on each TEID the legitimate source is always seen first, the spoof second,
and nothing follows it. On that input "first source wins" and "last source
wins" give the same verdicts, and the TEID-only key never meets two
receivers. The original R2 unit test sent one legitimate packet and one
spoof and checked only that the spoof was flagged. The live corpus sends
every packet on TEID 0x1, so spoofs and legitimate packets interleave on one
tunnel, and both faults show at once. The defect depends on the order of
packets on one TEID, not on any single packet, so the offline corpus could
not show it.

---

## Summary table

| # | Component | Symptom | Root cause | Severity |
|---|---|---|---|---|
| 1 | `core/Dockerfile` | Bring-up hangs forever, no error | `mongosh` never installed | High — total live-path bring-up failure |
| 2 | `core/entrypoint.sh` | AMF/UPF unreachable from `ran`, but core logs claim success | Regex didn't match YAML `- address:` list syntax; `re.sub` no-ops silently | High — silent, self-reported false success |
| 3 | `ran/Dockerfile` | `nr-binder` permission denied | Exec bit lost across multi-stage `COPY --from` | Low — affects one optional debug helper |
| 4 | `attacker/generate_attacks.py` | Zero packets ever reach the detector on `--send` | `sendp()` used on `Ether()`-less packets; malformed frames | **Critical — every live attack demo was broken from day one** |
| 5 | `docker-compose.yml` design | Detector/RAN silently stop working after any `core` rebuild | `network_mode: service:core` binds to a container ID, not a service name, at attach time | Medium — recurring operational trap during iteration |
| 6 | `core/entrypoint.sh` and the documented UE ping check | UE ping got replies, yet no UE packet ever crossed the UPF; UPF logged `ogs_tun_write() failed` | `ogstun` never configured (no address, link down, no NAT); `nr-binder` preloads `./libdevbnd.so` by a relative path the documented command could not resolve, so the ping ran unbound and bypassed the tunnel | High — the UE data path never worked and the check reported success; live detection results unaffected |
| 7 | `detector/rules.py` R2 (and `detector/baselines.py`) | Live corpus scored 16 FP (benign packet after a spoof) and 15 FN (spoof after a spoof) | Ownership moved to whichever source sent last; key was the TEID alone, not (receiving address, TEID) | High — a spoofer could take over a TEID; the only defect in detection logic |

All seven are now fixed in the working tree (Findings 1 to 4, 6 and 7 as
code changes; Finding 5 as a documented operational procedure in
`REPRODUCE.md`, which `scripts/lab_up.sh` also carries out on a full
bring-up). None of Findings 1 to 6 was reachable from `make test` or
`make eval`. Finding 7 was reachable, but no offline input triggered it; it
now has regression tests in `make test`, and `make live-score` scores the
exact live corpus packet by packet. See `PAPER.md` §8 for the
methodological lesson this suggests about validating passive
network-security tooling.
