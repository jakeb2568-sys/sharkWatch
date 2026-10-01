#!/usr/bin/env python3
"""
Generate deterministic sample captures for testing wirewatch.

    pip install scapy
    python3 scripts/make_samples.py

Writes samples/basic.pcap (normal traffic) and samples/edge_cases.pcap
(packets designed to trip up a careless parser). All traffic is synthetic,
no network access needed.
"""
from pathlib import Path

from scapy.all import (ARP, DNS, DNSQR, DNSRR, ICMP, IP, IPv6, TCP, UDP,
                       Dot1Q, Ether, Padding, Raw, RawPcapWriter, fragment)

OUT = Path(__file__).resolve().parent.parent / "samples"

CLIENT_MAC, ROUTER_MAC = "02:00:00:aa:aa:01", "02:00:00:bb:bb:01"
CLIENT, SERVER, DNS_SRV = "192.168.1.10", "93.184.216.34", "192.168.1.1"


def eth(src=CLIENT_MAC, dst=ROUTER_MAC):
    return Ether(src=src, dst=dst)


def write(path, frames, start, step=0.0125):
    """frames: list of bytes, or (bytes, wire_len) for snaplen-truncated frames."""
    w = RawPcapWriter(str(path), linktype=1, snaplen=65535)
    w.write_header(None)  # write_packet() below does not emit the file header itself
    for i, f in enumerate(frames):
        data, wirelen = (f if isinstance(f, tuple) else (bytes(f), None))
        data = bytes(data)
        t = start + i * step
        w.write_packet(data, sec=int(t), usec=round((t % 1) * 1e6),
                       caplen=len(data), wirelen=wirelen or len(data))
    w.close()


def basic():
    c, s = 51514, 80
    cseq, sseq = 1000, 5000
    http = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
    resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nhi"
    up = lambda **kw: eth() / IP(src=CLIENT, dst=SERVER, ttl=64, id=0x1001) / TCP(sport=c, dport=s, window=64240, **kw)
    down = lambda **kw: eth(ROUTER_MAC, CLIENT_MAC) / IP(src=SERVER, dst=CLIENT, ttl=54, id=0x2001) / TCP(sport=s, dport=c, window=65535, **kw)
    pkts = [
        # DNS lookup
        eth() / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=53001, dport=53)
        / DNS(id=0x1234, rd=1, qd=DNSQR(qname="example.com")),
        eth(ROUTER_MAC, CLIENT_MAC) / IP(src=DNS_SRV, dst=CLIENT) / UDP(sport=53, dport=53001)
        / DNS(id=0x1234, qr=1, ra=1, qd=DNSQR(qname="example.com"),
              an=DNSRR(rrname="example.com", rdata=SERVER, ttl=300)),
        # TCP three-way handshake, HTTP request/response, teardown
        up(flags="S", seq=cseq),
        down(flags="SA", seq=sseq, ack=cseq + 1),
        up(flags="A", seq=cseq + 1, ack=sseq + 1),
        up(flags="PA", seq=cseq + 1, ack=sseq + 1) / Raw(http),
        down(flags="A", seq=sseq + 1, ack=cseq + 1 + len(http)),
        down(flags="PA", seq=sseq + 1, ack=cseq + 1 + len(http)) / Raw(resp),
        up(flags="FA", seq=cseq + 1 + len(http), ack=sseq + 1 + len(resp)),
        down(flags="FA", seq=sseq + 1 + len(resp), ack=cseq + 2 + len(http)),
        up(flags="A", seq=cseq + 2 + len(http), ack=sseq + 2 + len(resp)),
        # ping
        eth() / IP(src=CLIENT, dst="8.8.8.8") / ICMP(type=8, id=0x42, seq=1) / Raw(b"abcdefgh"),
        eth(ROUTER_MAC, CLIENT_MAC) / IP(src="8.8.8.8", dst=CLIENT, ttl=117) / ICMP(type=0, id=0x42, seq=1) / Raw(b"abcdefgh"),
        # ARP who-has / is-at
        Ether(src=CLIENT_MAC, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=CLIENT_MAC, psrc=CLIENT, pdst=DNS_SRV),
        Ether(src=ROUTER_MAC, dst=CLIENT_MAC) / ARP(op=2, hwsrc=ROUTER_MAC, psrc=DNS_SRV, hwdst=CLIENT_MAC, pdst=CLIENT),
    ]
    return pkts


def edge_cases():
    pkts = []
    # 1. Tiny UDP packet padded to the 60-byte Ethernet minimum. The parser
    #    must use the IP total length, not the frame length, or it will count
    #    the padding as payload.
    pkts.append(eth() / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=40000, dport=9999) / Raw(b"x") / Padding(b"\x00" * 17))
    # 2. 802.1Q VLAN-tagged frame
    pkts.append(eth() / Dot1Q(vlan=42) / IP(src="10.42.0.5", dst="10.42.0.1") / UDP(sport=5353, dport=5353) / Raw(b"vlan"))
    # 3. IP header with options (IHL > 5) in front of TCP
    pkts.append(eth() / IP(src=CLIENT, dst=SERVER, options=b"\x01\x01\x01\x00") / TCP(sport=40001, dport=443, flags="S", seq=7))
    # 4. TCP header with options (MSS, SACK-permitted, timestamps, window scale)
    pkts.append(eth() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40002, dport=443, flags="S", seq=99,
                options=[("MSS", 1460), ("SAckOK", b""), ("Timestamp", (1, 0)), ("NOP", None), ("WScale", 7)]))
    # 5-7. A UDP datagram split into three IP fragments
    big = IP(src=CLIENT, dst=SERVER, id=0xBEEF) / UDP(sport=40003, dport=7777) / Raw(b"F" * 60)
    for frag in fragment(big, fragsize=32):
        pkts.append(eth() / frag)
    # 8. ICMP destination unreachable that quotes the header of the packet that caused it
    pkts.append(eth(ROUTER_MAC, CLIENT_MAC) / IP(src=DNS_SRV, dst=CLIENT) / ICMP(type=3, code=3)
                / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=40004, dport=12345))
    # 9. IPv6 (not decoded yet; should be labelled, not crash)
    pkts.append(eth() / IPv6(src="fe80::1", dst="ff02::1") / UDP(sport=546, dport=547))
    # 10. Capture snaplen cut the frame off in the middle of the TCP header
    #     (caplen 44 < wire length 54), like `tcpdump -s 44` would.
    full = bytes(eth() / IP(src=CLIENT, dst=SERVER) / TCP(sport=40005, dport=22, flags="S"))
    pkts.append((full[:14 + 20 + 10], len(full)))
    # 11. Garbage IHL (claims a 8-byte IP header, which is impossible)
    raw = bytearray(bytes(eth() / IP(src=CLIENT, dst=SERVER) / UDP(sport=1, dport=2)))
    raw[14] = 0x42
    pkts.append(bytes(raw))
    # 12. Frame too short to even hold an Ethernet header
    pkts.append(b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a")
    return pkts


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write(OUT / "basic.pcap", basic(), start=1_700_000_000.0)
    write(OUT / "edge_cases.pcap", edge_cases(), start=1_700_000_100.0)
    print(f"wrote {OUT/'basic.pcap'} and {OUT/'edge_cases.pcap'}")
