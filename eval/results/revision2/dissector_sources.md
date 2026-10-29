# Dissector source evidence (read 2026-10-29)

## Scapy 2.4.4 and 2.7.0 (identical) — scapy/contrib/gtp.py, GTP_U_Header.guess_payload_class
- if E == 1: next_ex 0x85 -> GTPPDUSessionContainer, else GTPHeader.guess_payload_class
- if gtp_type == 255 (G-PDU): first payload byte 0x45..0x4E -> IP; (byte & 0xF0) == 0x60 -> IPv6; else -> PPP
- otherwise GTPHeader.guess_payload_class (bare outer 0x00 -> Raw)
- No branch returns GTP_U_Header for a G-PDU payload.

## Wireshark 4.6.6 — epan/dissectors/packet-gtp.c
- preference gtp.dissect_tpdu_as, default GTP_TPDU_AS_TPDU_HEUR ("TPDU Heuristic"); options none, heuristic, pdcp-lte, pdcp-nr, sync, eth, custom (lines 99-105, 1048-1056, 13155)
- for a T-PDU: dissector_try_heuristic over heuristic list "gtp.tpdu"; if none accepts -> hf_gtp_tpdu_data ("T-PDU Data") (lines ~11056-11065)
- heuristics registered on "gtp.tpdu": dissect_ip_heur (packet-ip.c:3271, "IP over GTP") and dissect_eth_heur (packet-gtp.c:13336, "Ethernet over GTP")
- dissect_ip_heur (packet-ip.c:2567): version 6 -> IPv6 heuristic; requires version 4, IHL >= 5 and IPv4 total length == reported length
- no GTP heuristic on "gtp.tpdu" -> nested GTP-U header shown as T-PDU data under the default preference

## Zeek 8.2.2 — src/packet_analysis/protocol/gtpv1/gtpv1-analyzer.pac, process_g_pdu (~line 711-750); GTPv1.cc
- if payload ip_v != 4 and != 6 -> violate("non-IP packet in GTPv1"), return false (not forwarded)
- header length accounts for optional field and extension headers
- GTPv1.cc forwards only after IP::ParsePacket OK

## Zeek 8.2.2 GTP-in-GTP violation — gtpv1-analyzer.pac:660-665
- if the packet's encapsulation stack already ends in a GTPv1 tunnel -> violate("GTP-in-GTP"), return false
- reached only when a GTP packet arrives over UDP inside an existing GTPv1 tunnel, i.e. the IP-wrapped form
