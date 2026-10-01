"""Draw Figs. 1-6 of the journal manuscript in colour at true print size.

Usage: python3 paper/figures/make_manuscript_figures.py [out_dir]
Writes image1.png ... image6.png (default: paper/figures/manuscript/).
Full-width figures are drawn 6.7 in wide and column figures 3.2 in wide,
so the text prints at its designed size.
"""
import os
import sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch
import numpy as np

OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), "manuscript")
os.makedirs(OUT, exist_ok=True)
DPI = 400
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 7.5})

NAVY = "#1b2a41"
CP_FC = "#dbe8f5"          # control plane / core NFs
UP_FC = "#cfe3f7"          # user plane
UP_EC = "#1f5fa8"
LEGIT = "#2e7d32"          # legitimate traffic
LEGIT_FC = "#e3f1e4"
ATTACK = "#c62828"         # crafted / adversary
ATTACK_FC = "#fde4e2"
DET = "#1f5fa8"            # detector
DET_FC = "#e1ecf8"
GREY = "#5f6b7a"
UNDEC_FC = "#fbd9a5"       # left undecoded by default dissection
UNDEC_EC = "#c77700"
OFF_FC = "#f3eefa"
OFF_EC = "#6a4c93"


def canvas(w, h, xmax, ymax):
    fig = plt.figure(figsize=(w, h), dpi=DPI)
    ax = fig.add_axes([0, 0, 1, 1])
    ax.set_xlim(0, xmax)
    ax.set_ylim(0, ymax)
    ax.axis("off")
    return fig, ax


def box(ax, x, y, w, h, text="", fc="white", ec=NAVY, lw=1.0, fs=7.5,
        bold=False, color=NAVY, ls="-", r=0.6, style=None, ha="center"):
    p = FancyBboxPatch((x, y), w, h, boxstyle=f"round,pad=0,rounding_size={r}",
                       fc=fc, ec=ec, lw=lw, ls=ls, zorder=2)
    ax.add_patch(p)
    if text:
        tx = x + w / 2 if ha == "center" else x + 0.8
        ax.text(tx, y + h / 2, text, ha=ha, va="center", fontsize=fs,
                fontweight="bold" if bold else "normal", color=color,
                zorder=3, fontstyle=style or "normal", linespacing=1.25)
    return p


def arrow(ax, p1, p2, color=NAVY, lw=1.0, ls="-", head=6, cs="arc3,rad=0",
          both=False):
    a = FancyArrowPatch(p1, p2, arrowstyle=("<|-|>" if both else "-|>"),
                        mutation_scale=head, color=color, lw=lw, ls=ls,
                        connectionstyle=cs, zorder=4, shrinkA=0, shrinkB=0)
    ax.add_patch(a)


def save(fig, name):
    fig.savefig(f"{OUT}/{name}", dpi=DPI, facecolor="white")
    plt.close(fig)


# ---------------------------------------------------------------- Fig. 1
def fig1():
    fig, ax = canvas(6.7, 2.55, 134, 51)
    # control plane
    ax.text(67, 49, "Control plane (5GC service-based architecture)", ha="center",
            va="center", fontsize=7, color=GREY, style="italic")
    box(ax, 44, 38, 14, 8, "AMF", fc=CP_FC)
    box(ax, 62, 38, 14, 8, "SMF", fc=CP_FC)
    # user plane row
    Y, H = 18, 11
    box(ax, 1, Y, 17, H, "UE\n(subscriber)")
    box(ax, 26, Y, 17, H, "gNB\n(RAN)")
    box(ax, 55, Y, 20, H, "UPF\n(N3 termination)", fc=UP_FC, ec=UP_EC, lw=1.6, fs=7)
    box(ax, 87, Y, 20, H, "UPF\n(session anchor)", fc=UP_FC, ec=UP_EC, fs=7)
    box(ax, 115, Y, 18, H, "Data network")
    ym = Y + H / 2
    arrow(ax, (18, ym), (26, ym))
    ax.text(22, ym + 1.6, "Uu", ha="center", fontsize=6.5, color=GREY)
    arrow(ax, (43, ym), (55, ym), lw=2.0, color=UP_EC)
    ax.text(49, ym + 1.6, "N3", ha="center", fontsize=7.5, fontweight="bold", color=UP_EC)
    ax.text(49, ym - 3.0, "GTP-U", ha="center", fontsize=6.5, color=UP_EC)
    arrow(ax, (75, ym), (87, ym), lw=2.0, color=UP_EC)
    ax.text(81, ym + 1.6, "N9", ha="center", fontsize=7.5, fontweight="bold", color=UP_EC)
    ax.text(81, ym - 3.0, "GTP-U", ha="center", fontsize=6.5, color=UP_EC)
    arrow(ax, (107, ym), (115, ym))
    ax.text(111, ym + 1.6, "N6", ha="center", fontsize=6.5, color=GREY)
    # N2 / N4 signalling
    ax.plot([37, 49], [Y + H, 38], ls="--", color=GREY, lw=0.9, zorder=1)
    ax.text(40.5, 34.5, "N2", fontsize=6.5, color=GREY)
    ax.plot([69, 66], [38, Y + H], ls="--", color=GREY, lw=0.9, zorder=1)
    ax.text(68.5, 33.5, "N4", fontsize=6.5, color=GREY)
    # capture segment bracket (N3 .. N9)
    ax.plot([43, 43, 55, 55], [14.6, 13.0, 13.0, 14.6], color=DET, lw=1.0)
    ax.plot([49, 49], [13.0, 11.0], color=DET, lw=1.0)
    ax.text(49, 9.4, "passive capture point in this work (N3)",
            ha="left", va="center", fontsize=6.8, color=DET)
    # adversary positions
    ax.annotate("Position 1: untrusted\nsubscriber device", xy=(9.5, Y + H), xytext=(12, 41),
                ha="center", va="center", fontsize=6.6, color=ATTACK,
                arrowprops=dict(arrowstyle="-|>", color=ATTACK, lw=1.0, mutation_scale=6))
    ax.annotate("Position 2: on-path injector on N3\n(compromised gNB, transport insider)",
                xy=(45.6, ym - 0.8), xytext=(24, 5), ha="center", va="center",
                fontsize=6.6, color=ATTACK,
                arrowprops=dict(arrowstyle="-|>", color=ATTACK, lw=1.0, mutation_scale=6,
                                connectionstyle="arc3,rad=0.25"))
    save(fig, "image1.png")


# ---------------------------------------------------------------- Fig. 2
def fig2():
    fig, ax = canvas(6.7, 2.75, 134, 55)
    cols = [
        ("(a) Conformant", [("Outer IP  |  UDP 2152", "o"), ("GTP-U header (G-PDU)", "o"),
                            ("Inner IP (subscriber)", "n"), ("TCP / UDP payload", "n")],
         "Dissects fully.\nOne decapsulation.\nNo rule fires."),
        ("(b) Bare nested", [("Outer IP  |  UDP 2152", "o"), ("GTP-U header (TEID$_1$)", "o"),
                             ("GTP-U header (TEID$_2$)", "u"), ("Innermost IP packet", "u")],
         "Dissection stops after the\nouter header; the rest is\nguessed as PPP or Raw.\nNaive detector: 0 of 120."),
        ("(c) IP-wrapped nested", [("Outer IP  |  UDP 2152", "o"), ("GTP-U header (TEID$_1$)", "o"),
                                   ("Inner IP  |  UDP 2152", "n"), ("GTP-U header (TEID$_2$)", "n"),
                                   ("Innermost IP packet", "n")],
         "Dissects fully, eight layers:\nthe inner UDP port rebinds\nGTP-U, so the naive\ndetector catches it."),
        ("(d) Plane crossing", [("Outer IP  |  UDP 2152", "o"), ("GTP-U header (G-PDU)", "o"),
                                ("Inner IP  |  UDP 8805 / SCTP", "a"), ("PFCP or NGAP signalling", "a")],
         "Dissects fully; visible in\nlayers the dissector already\ndecodes, so both detectors\ncatch it."),
    ]
    fills = {"o": (UP_FC, UP_EC), "n": ("white", NAVY), "u": (UNDEC_FC, UNDEC_EC),
             "a": (ATTACK_FC, ATTACK)}
    W, LH, X0, STEP = 30, 5.2, 3, 33
    for i, (title, layers, desc) in enumerate(cols):
        x = X0 + i * STEP
        ax.text(x + W / 2, 52.5, title, ha="center", va="center", fontsize=8, fontweight="bold",
                color=ATTACK if i == 1 else NAVY)
        y = 45.5
        for txt, kind in layers:
            fc, ec = fills[kind]
            box(ax, x, y, W, LH - 0.4, txt, fc=fc, ec=ec, fs=6.8, r=0.5)
            y -= LH
        if i == 1:
            p = FancyBboxPatch((x - 0.9, y + LH - 0.9), W + 1.8, 4 * LH + 1.3,
                               boxstyle="round,pad=0,rounding_size=0.8", fc="none",
                               ec=ATTACK, lw=1.6, zorder=5)
            ax.add_patch(p)
        ax.text(x + W / 2, 15.5, desc, ha="center", va="center", fontsize=6.6, color=NAVY,
                linespacing=1.3)
    # legend
    lx = 9
    for fc, ec, lab in [(UP_FC, UP_EC, "outer tunnel"), ("white", NAVY, "decoded by default dissection"),
                        (UNDEC_FC, UNDEC_EC, "left undecoded (PPP or Raw)"),
                        (ATTACK_FC, ATTACK, "control-plane payload")]:
        box(ax, lx, 1.4, 3.2, 2.6, fc=fc, ec=ec, r=0.3)
        ax.text(lx + 4.2, 2.7, lab, va="center", fontsize=6.3, color=NAVY)
        lx += 4.2 + len(lab) * 0.98 + 4.5
    save(fig, "image2.png")


# ---------------------------------------------------------------- Fig. 3
def fig3():
    fig, ax = canvas(6.7, 3.35, 134, 67)
    # host frame
    box(ax, 0.5, 0.5, 133, 66, fc="none", ec=GREY, ls="--", lw=0.8, r=1.0)
    ax.text(2.2, 64, "Docker Compose host: one bridge network, lab 10.10.10.0/24",
            fontsize=6.8, color=GREY, style="italic", va="center")
    # RAN container
    box(ax, 3, 36, 25, 20, fc=LEGIT_FC, ec=LEGIT, lw=1.2)
    ax.text(15.5, 52.6, "ran  10.10.10.20", ha="center", fontsize=6.6, color=LEGIT, fontweight="bold")
    box(ax, 5, 44.5, 21, 5.4, "UERANSIM gNB", fs=6.8)
    box(ax, 5, 38, 21, 5.4, "UERANSIM UE\nIPv4 PDU session", fs=6.2)
    # mongo
    box(ax, 3, 6, 25, 8, "mongo  10.10.10.5\nsubscriber database", fs=6.4, fc="#f1f3f5", ec=GREY)
    # core netns
    box(ax, 38, 6, 60, 52, fc="#f7fafd", ec=UP_EC, lw=1.4, r=1.0)
    ax.text(68, 55.2, "core container network namespace  10.10.10.10", ha="center",
            fontsize=6.9, color=UP_EC, fontweight="bold")
    # eth0 interface bar
    box(ax, 38.8, 9, 3.4, 44, fc=UP_EC, ec=UP_EC, r=0.4)
    ax.text(40.5, 31, "eth0  (N2 + N3)", rotation=90, ha="center", va="center",
            fontsize=6.6, color="white", fontweight="bold")
    # Open5GS NFs
    box(ax, 46, 41, 48, 11.5, fc=CP_FC, ec=NAVY, r=0.6)
    ax.text(70, 50.3, "Open5GS 5G core", ha="center", fontsize=6.8, fontweight="bold")
    for j, nf in enumerate(["AMF", "SMF", "NRF", "UDM"]):
        box(ax, 47.5 + j * 11.6, 42.3, 10.4, 5.2, nf, fs=6.2, r=0.4)
    box(ax, 46, 30, 30, 8.6, "UPF\n(N3 termination)", fc=UP_FC, ec=UP_EC, lw=1.3, fs=6.8, bold=True)
    box(ax, 80, 30, 14, 8.6, "N6 to data\nnetwork (NAT)", fs=6.0, fc="white", ec=GREY)
    arrow(ax, (76, 34.3), (80, 34.3), color=GREY, lw=0.9)
    # injector and detector, both in the core namespace
    box(ax, 46, 9, 22, 16.5, fc=ATTACK_FC, ec=ATTACK, lw=1.2)
    ax.text(57, 22.6, "attacker container", ha="center", fontsize=6.6, color=ATTACK, fontweight="bold")
    ax.text(57, 15.6, "Scapy, raw socket,\nshares core namespace;\nnot a UE, no PDU session",
            ha="center", va="center", fontsize=6.0, color=NAVY, linespacing=1.25)
    box(ax, 72, 9, 22, 16.5, fc=DET_FC, ec=DET, lw=1.2)
    ax.text(83, 22.6, "detector container", ha="center", fontsize=6.6, color=DET, fontweight="bold")
    ax.text(83, 15.6, "passive sniff of eth0,\nread-only, never in the\nforwarding path",
            ha="center", va="center", fontsize=6.0, color=NAVY, linespacing=1.25)
    # traffic arrows
    arrow(ax, (28, 47.2), (38.8, 47.2), color=GREY, lw=1.0)
    ax.text(33.4, 48.4, "N2 NGAP", ha="center", fontsize=5.8, color=GREY)
    arrow(ax, (28, 40.5), (38.8, 40.5), color=LEGIT, lw=1.6)
    ax.text(33.4, 39.4, "N3 GTP-U\n(legitimate)", ha="center", va="top", fontsize=5.8, color=LEGIT)
    arrow(ax, (42.2, 46), (46, 46), color=GREY, lw=0.9)
    arrow(ax, (42.2, 34.3), (46, 34.3), color=LEGIT, lw=1.4)
    # injector writes onto eth0
    arrow(ax, (46, 17), (42.2, 17), color=ATTACK, lw=1.6)
    ax.text(15.5, 24.5, "crafted GTP-U written onto\neth0 by the attacker container:\nouter source 10.10.10.20 (gNB)\n"
            "or 10.10.10.66 (rogue),\ndestination the UPF, 10.10.10.10", ha="center", va="center",
            fontsize=5.6, color=ATTACK, linespacing=1.2)
    arrow(ax, (29.5, 22), (38.6, 18.2), color=ATTACK, lw=0.8)
    # passive copy to detector
    ax.plot([42.2, 83], [27.6, 27.6], color=DET, lw=1.0, ls="--", zorder=4)
    arrow(ax, (83, 27.6), (83, 25.5), color=DET, lw=1.0)
    ax.text(62.5, 28.3, "passive read of every frame on eth0", ha="center", fontsize=5.4, color=DET)
    # outputs
    box(ax, 103, 40, 28, 12, "findings (JSON lines)\nlive.json metrics\nlive dashboard :8090",
        fs=6.2, fc="white", ec=DET)
    ax.plot([94, 99, 99], [17, 17, 46], color=DET, lw=1.0)
    arrow(ax, (99, 46), (103, 46), color=DET, lw=1.0)
    # offline path
    box(ax, 103, 6, 28, 30, fc=OFF_FC, ec=OFF_EC, ls="--", lw=1.0, r=0.8)
    ax.text(117, 33.2, "offline path (no core)", ha="center", fontsize=6.6, color=OFF_EC, fontweight="bold")
    box(ax, 105.5, 23.5, 23, 7, "corpus generator\nlabelled pcap + manifest", fs=5.9)
    arrow(ax, (117, 23.5), (117, 20.5), color=OFF_EC)
    box(ax, 105.5, 13.5, 23, 7, "same rule module\n(rules.py)", fs=5.9)
    arrow(ax, (117, 13.5), (117, 11.5), color=OFF_EC)
    ax.text(117, 9.3, "precision, recall, FPR", ha="center", fontsize=5.9, color=OFF_EC)
    # links mongo -> core
    arrow(ax, (28, 10), (38.8, 10), color=GREY, lw=0.8, ls=":", both=True)
    save(fig, "image3.png")


# ---------------------------------------------------------------- Fig. 4
def fig4():
    fig, ax = canvas(3.2, 5.1, 64, 95)
    ax.set_ylim(-7, 95)
    X, W = 3, 44
    steps = [
        (88, 5.2, "Captured frame", False),
        (79.5, 5.6, "GTP-U layer present?", False),
        (70, 6.4, "Take the outer payload as\nthe dissector returned it", False),
        (60.5, 6.4, "Already decoded as IPv4,\nIPv6 or a GTP header?", False),
        (40, 16.5, "PLAUSIBILITY GATE on the raw bytes\nversion 1, PT bit set\n"
                   "message type in {01, 02, 1a, 1b, fe, ff}\n8 + declared length matches the\n"
                   "bytes present (padding up to 4 B)\nG-PDU declares at least 20 B", True),
        (32, 5.6, "Re-dissect those bytes as GTP-U", True),
        (21.5, 7.6, "GUARD: nested header must\nforward a routable IPv4 or\nIPv6 packet", False),
    ]
    for y, h, t, b in steps:
        box(ax, X, y, W, h, t, fs=6.2 if len(t) < 60 else 5.6, bold=b and len(t) < 40,
            fc=(UP_FC if b else "white"), ec=(UP_EC if b else NAVY), lw=(1.5 if b else 1.0), r=0.8)
    for (y1, h1, _, _), (y2, h2, _, _) in zip(steps, steps[1:]):
        arrow(ax, (X + W / 2, y1), (X + W / 2, y2 + h2), lw=1.0)
    # side exits
    def side(y, label):
        arrow(ax, (X + W, y), (X + W + 3.4, y), color=GREY, lw=0.9)
        ax.text(X + W + 4.2, y, label, va="center", fontsize=5.6, color=GREY, linespacing=1.2)
    side(82.3, "no:\ndiscard")
    side(63.7, "yes: to\nrules\nas is")
    side(48.2, "fails:\nordinary\npayload,\nto rules")
    # rules block
    arrow(ax, (X + W / 2, 21.5), (X + W / 2, 18.4), lw=1.0)
    rules = [("R1", "nested GTP-U header"), ("R2", "TEID owner conflict"),
             ("R3", "inner SCTP, or UDP to\nPFCP / GTP-C / GTP-U"), ("R4", "inner dst is a core NF")]
    y = 13.6
    for rid, txt in rules:
        hh = 5.4 if "\n" in txt else 3.8
        box(ax, X, y + 3.8 - hh, 7, hh, rid, fc=CP_FC, bold=True, fs=6.4, r=0.5)
        box(ax, X + 8, y + 3.8 - hh, W - 8, hh, txt, fs=5.8, r=0.5)
        y -= hh + 0.6
    ax.text(X + W / 2, -5.0, "R2 reads the outer header only and needs no re-parse.",
            ha="center", fontsize=5.4, color=GREY, style="italic")
    save(fig, "image4.png")


# ---------------------------------------------------------------- Fig. 5
def fig5():
    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(6.7, 2.35), dpi=DPI,
                                 gridspec_kw={"width_ratios": [2.4, 1]})
    cl = ["gtp_in_gtp", "teid_spoof", "pfcp_smuggle", "ngap_smuggle", "inner_to_core"]
    naive, robust = [0, 1, 1, 1, 1], [1] * 5
    x, w = np.arange(5), 0.38
    a1.bar(x - w / 2, naive, w, color="#e08a1e", edgecolor=NAVY, lw=0.6, label="naive (default dissection)")
    a1.bar(x + w / 2, robust, w, color=UP_EC, edgecolor=NAVY, lw=0.6, label="robust (targeted re-parse)")
    for i in range(5):
        a1.text(i - w / 2, naive[i] + 0.03, f"{naive[i]:.1f}", ha="center", fontsize=6.3)
        a1.text(i + w / 2, 1.03, "1.0", ha="center", fontsize=6.3)
    a1.set_xticks(x)
    a1.set_xticklabels(cl, fontsize=6.4)
    a1.set_ylim(0, 1.32)
    a1.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    a1.set_ylabel("Recall")
    a1.set_title("(a) Per-class recall, identical corpus and rule logic", fontsize=7.5)
    a1.legend(loc="upper center", ncol=2, frameon=False, fontsize=6.5)
    a2.bar([0, 1], [0.8889, 1.0], 0.55, color=["#e08a1e", UP_EC], edgecolor=NAVY, lw=0.6)
    a2.text(0, 0.92, "0.889", ha="center", fontsize=6.5)
    a2.text(1, 1.03, "1.0", ha="center", fontsize=6.5)
    a2.set_xticks([0, 1])
    a2.set_xticklabels(["naive", "robust"])
    a2.set_ylim(0, 1.32)
    a2.set_yticks([0, 0.25, 0.5, 0.75, 1.0])
    a2.set_ylabel("Overall F1")
    a2.set_title("(b) Overall F1", fontsize=7.5)
    fig.tight_layout(pad=0.4)
    save(fig, "image5.png")


# ---------------------------------------------------------------- Fig. 6
def fig6():
    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False})
    fig, a = plt.subplots(figsize=(3.2, 1.95), dpi=DPI)
    v = [686, 627, 1187, 1616, 2332]
    lab = ["mean", "P50", "P95", "P99", "max"]
    col = [UP_EC, "#4f9bd6", "#e08a1e", "#d9541e", ATTACK]
    a.bar(lab, v, color=col, edgecolor=NAVY, lw=0.6, width=0.58)
    for i, y in enumerate(v):
        a.text(i, max(y, 686) + 40, f"{y:,}", ha="center", fontsize=6.2)
    a.axhline(686, ls="--", color=GREY, lw=0.8)
    a.text(-0.35, 2150, "dashed line: mean,\nabout 1,450 pkt/s single core", ha="left", va="center",
           fontsize=5.8, color=GREY)
    a.set_ylabel("Per-packet cost (µs)", fontsize=6.8)
    a.tick_params(labelsize=6.4)
    a.set_ylim(0, 2650)
    fig.tight_layout(pad=0.3)
    save(fig, "image6.png")


for f in (fig1, fig2, fig3, fig4, fig5, fig6):
    f()
print(f"wrote image1.png .. image6.png to {OUT}")
