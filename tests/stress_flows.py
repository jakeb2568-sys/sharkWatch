#!/usr/bin/env python3
"""
Resource-exhaustion tests for the flow tracker.

    python3 tests/stress_flows.py ./sharkwatch

Two attacks an IDS has to survive without running out of memory:
  1. SYN flood: 500,000 SYNs from random source addresses and ports, so
     every packet would create a new flow if nothing stopped it.
  2. Reassembly bomb: 20,000 connections that each send the first piece of
     a split TLS ClientHello and never the rest, so each one would pin a
     reassembly buffer forever.
Each test reports peak memory (max RSS) and checks that the limits fired.
Linux only (uses /usr/bin/time). No scapy needed: packets are built by hand.
"""
import random
import re
import struct
import subprocess
import sys
import tempfile
from pathlib import Path


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return ~s & 0xFFFF


def tcp_packet(src, dst, sport, dport, seq, flags, payload=b""):
    tcp = struct.pack("!HHIIBBHHH", sport, dport, seq, 0, 5 << 4, flags, 64240, 0, 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, src, dst)
    ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
    eth = b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + b"\x08\x00"
    return eth + ip + tcp


def write_pcap(path, packets):
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for i, p in enumerate(packets):
            f.write(struct.pack("<IIII", 1_700_000_000 + i // 100000, i % 100000, len(p), len(p)))
            f.write(p)


def run(binary, pcap, *args):
    r = subprocess.run(["/usr/bin/time", "-v", binary, "-r", str(pcap), *args],
                       capture_output=True, text=True)
    rss_kb = int(re.search(r"Maximum resident set size \(kbytes\): (\d+)", r.stderr).group(1))
    return r.returncode, r.stderr, rss_kb / 1024


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    binary = sys.argv[1]
    rng = random.Random(7)
    server = bytes([10, 9, 9, 9])
    ok = True

    with tempfile.TemporaryDirectory() as d:
        # 1. SYN flood
        flood = Path(d) / "synflood.pcap"
        write_pcap(flood, (tcp_packet(rng.randbytes(4), server, rng.randrange(1024, 65536), 443,
                                      rng.randrange(2**32), 0x02) for _ in range(500_000)))
        for limit in ([], ["-m", "1000"]):
            rc, err, mb = run(binary, flood, *limit)
            evicted = int(re.search(r"(\d+) flows evicted", err).group(1))
            peak = int(re.search(r"peak (\d+) active", err).group(1))
            cap = int(limit[1]) if limit else 65536
            good = rc == 0 and peak <= cap and evicted > 0
            ok &= good
            print(f"SYN flood, 500,000 SYNs, cap {cap:>6}: peak {peak} flows, {evicted} evicted, "
                  f"max RSS {mb:.0f} MB  {'OK' if good else 'FAIL'}")

        # 2. Reassembly bomb: first 10 bytes of a ClientHello, then silence
        bomb = Path(d) / "reassembly_bomb.pcap"
        hello_start = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03"
        pkts = []
        for i in range(20_000):
            src = struct.pack("!I", 0x0A010000 + i)
            pkts.append(tcp_packet(src, server, 40000, 443, 100, 0x02))
            pkts.append(tcp_packet(src, server, 40000, 443, 101, 0x18, hello_start))
        write_pcap(bomb, pkts)
        rc, err, mb = run(binary, bomb)
        skipped = int(re.search(r"(\d+) reassemblies skipped", err).group(1))
        good = rc == 0 and skipped > 0 and mb < 200
        ok &= good
        print(f"Reassembly bomb, 20,000 stalled hellos: {skipped} reassemblies refused by the "
              f"64 MB budget, max RSS {mb:.0f} MB  {'OK' if good else 'FAIL'}")

    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
