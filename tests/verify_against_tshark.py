#!/usr/bin/env python3
"""
Check sharkwatch's decoding field-by-field against Wireshark's (tshark).

    python3 tests/verify_against_tshark.py ./sharkwatch samples/*.pcap

For every packet, runs `sharkwatch -T` and `tshark -T fields` on the same file
and compares IPs, protocol, TTL, ports, TCP flags/seq/ack/len, UDP length and
ICMP type/code. Exits non-zero on any mismatch.
"""
import subprocess
import sys

COLUMNS = ["frame", "ip.src", "ip.dst", "ip.proto", "ip.ttl", "srcport", "dstport",
           "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "udp.length",
           "icmp.type", "icmp.code"]
L4_COLUMNS = COLUMNS[5:]

# tshark has separate tcp/udp port fields; we merge them into srcport/dstport.
TSHARK_FIELDS = ["frame.number", "ip.src", "ip.dst", "ip.proto", "ip.ttl",
                 "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
                 "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "udp.length",
                 "icmp.type", "icmp.code", "_ws.expert.message"]


def norm(v):
    """'0x0012' and '18' should compare equal."""
    v = v.strip()
    if v.startswith("0x"):
        return str(int(v, 16))
    return v


def run_sharkwatch(binary, pcap):
    out = subprocess.run([binary, "-T", "-r", pcap], capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split("\t")
        row = dict(zip(COLUMNS, map(norm, parts[:len(COLUMNS)])))
        row["error"] = parts[len(COLUMNS)] if len(parts) > len(COLUMNS) else ""
        rows[row["frame"]] = row
    return rows


def run_tshark(pcap):
    cmd = ["tshark", "-r", pcap,
           "-o", "ip.defragment:FALSE",     # we don't reassemble, so neither should it
           "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=f"]            # outer header only (ICMP errors quote an inner one)
    for f in TSHARK_FIELDS:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        p = dict(zip(TSHARK_FIELDS, line.split("\t")))
        rows[p["frame.number"]] = {
            "frame": p["frame.number"], "ip.src": p["ip.src"], "ip.dst": p["ip.dst"],
            "ip.proto": norm(p["ip.proto"]), "ip.ttl": p["ip.ttl"],
            "srcport": p["tcp.srcport"] or p["udp.srcport"],
            "dstport": p["tcp.dstport"] or p["udp.dstport"],
            "tcp.flags": norm(p["tcp.flags"]), "tcp.seq_raw": p["tcp.seq_raw"],
            "tcp.ack_raw": p["tcp.ack_raw"], "tcp.len": p["tcp.len"],
            "udp.length": p["udp.length"], "icmp.type": p["icmp.type"],
            "icmp.code": p["icmp.code"], "expert": p.get("_ws.expert.message", ""),
        }
    return rows


def compare(binary, pcap):
    ours, theirs = run_sharkwatch(binary, pcap), run_tshark(pcap)
    mismatches = checked = 0
    print(f"== {pcap}: {len(ours)} packets")
    if ours.keys() != theirs.keys():
        print(f"  packet count differs: sharkwatch {len(ours)}, tshark {len(theirs)}")
        return 1

    for frame, w in ours.items():
        t = theirs[frame]
        if w["error"]:
            # Malformed packets: we stop decoding at the first bad header,
            # tshark sometimes salvages more. Report side by side, don't diff.
            print(f"  frame {frame:>3}: sharkwatch flagged \"{w['error']}\""
                  f"  | tshark: {t['expert'] or '(no warning)'}")
            continue

        cols = COLUMNS[1:]
        if not w["ip.src"]:
            cols = [c for c in cols if c not in L4_COLUMNS]   # non-IPv4 (ARP, IPv6): L2 only for now
        if w["ip.proto"] == "1":
            # For ICMP errors tshark also dissects the quoted inner packet and
            # reports *its* ports; those aren't fields of this packet.
            cols = [c for c in cols if c not in ("srcport", "dstport", "udp.length",
                                                 "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len")]
        for c in cols:
            checked += 1
            if w[c] != t[c]:
                mismatches += 1
                print(f"  frame {frame:>3}: {c:<12} sharkwatch={w[c]!r:<18} tshark={t[c]!r}")

    print(f"  {checked} fields compared, {mismatches} mismatches")
    return mismatches


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    bad = sum(compare(sys.argv[1], p) for p in sys.argv[2:])
    print("\nPASS" if bad == 0 else f"\nFAIL: {bad} mismatches")
    sys.exit(1 if bad else 0)
