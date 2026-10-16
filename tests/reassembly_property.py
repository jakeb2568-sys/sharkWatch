#!/usr/bin/env python3
"""
Property-based test of TCP stream reassembly.

    python3 tests/reassembly_property.py ./sharkwatch [connections] [seed]

Builds connections that each carry a real TLS ClientHello with a unique
hostname, then mangles delivery the way real networks do:
  - cuts the hello into 1-6 segments at random points,
  - shuffles their order,
  - duplicates some of them (retransmissions),
  - starts some sequence numbers just below 2^32 so they wrap mid-hello.
The property: for every connection, sharkwatch decodes exactly one complete
ClientHello, and its SNI is the right hostname. Needs scapy.
"""
import random
import ssl
import subprocess
import sys
import tempfile
from pathlib import Path

from scapy.all import IP, TCP, Ether, Raw, RawPcapWriter


def client_hello(sni):
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(["h2", "http/1.1"])
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def build(path, n, rng):
    expected = {}
    w = RawPcapWriter(str(path), linktype=1, snaplen=65535)
    w.write_header(None)
    t = 0

    def put(pkt):
        nonlocal t
        raw = bytes(pkt)
        w.write_packet(raw, sec=1_700_000_000 + t // 1000, usec=(t % 1000) * 1000,
                       caplen=len(raw), wirelen=len(raw))
        t += 1

    for i in range(n):
        cport = 10000 + i
        sni = f"host{i}-{rng.randrange(10**6)}.example.org"
        hello = client_hello(sni)
        expected[str(cport)] = sni
        isn = rng.choice([rng.randrange(2**32), 2**32 - rng.randrange(1, len(hello))])
        cli = ("10.1.%d.%d" % (i // 250, i % 250 + 1), cport)
        srv = ("10.9.9.9", 443)

        def seg(flags, seq, ack, data=b"", src=cli, dst=srv):
            p = Ether() / IP(src=src[0], dst=dst[0]) / TCP(sport=src[1], dport=dst[1], flags=flags,
                                                           seq=seq % 2**32, ack=ack % 2**32)
            return p / Raw(data) if data else p

        put(seg("S", isn, 0))
        put(seg("SA", 777, isn + 1, src=srv, dst=cli))
        put(seg("A", isn + 1, 778))

        k = rng.randint(1, 6)
        cuts = sorted(rng.sample(range(1, len(hello)), k - 1))
        bounds = [0] + cuts + [len(hello)]
        pieces = [seg("PA", isn + 1 + a, 778, hello[a:b]) for a, b in zip(bounds, bounds[1:])]
        order = pieces[:]
        rng.shuffle(order)
        for p in list(order):
            if rng.random() < 0.3:
                order.insert(rng.randrange(len(order) + 1), p)   # retransmission
        for p in order:
            put(p)
    w.close()
    return expected


def main():
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    binary = sys.argv[1]
    n = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
    seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
    rng = random.Random(seed)

    with tempfile.TemporaryDirectory() as d:
        pcap = Path(d) / "reassembly.pcap"
        expected = build(pcap, n, rng)
        out = subprocess.run([binary, "-T", "-r", str(pcap)], capture_output=True,
                             text=True, check=True).stdout

    cols = {"srcport": 5, "tls.sni": 24, "tls.state": 26, "tcp.retrans": 29}
    seen = {}
    for line in out.splitlines():
        f = line.split("\t")
        if (len(f) > 29 and f[cols["tls.state"]] in ("full", "reassembled")
                and f[cols["tcp.retrans"]] != "1"):
            seen.setdefault(f[cols["srcport"]], []).append(f[cols["tls.sni"]])

    bad = 0
    for port, sni in expected.items():
        got = seen.get(port, [])
        if got != [sni]:
            bad += 1
            if bad <= 5:
                print(f"  connection {port}: expected [{sni!r}], got {got!r}")
    print(f"{n} connections, {n - bad} reassembled correctly, {bad} wrong")
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
