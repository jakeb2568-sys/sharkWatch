#!/usr/bin/env python3
"""
Generate deterministic sample captures for testing sharkwatch.

    pip install scapy
    python3 scripts/make_samples.py

Writes:
  samples/basic.pcap       normal traffic
  samples/edge_cases.pcap  packets designed to trip up a careless header parser
  samples/app_layer.pcap   DNS, HTTP, TLS and plaintext logins, plus hostile
                           application data (DNS compression loops, escape codes)

All traffic is synthetic and the credentials are fake; no network access needed.
"""
import ssl
import struct
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


def tls_client_hello(sni, alpn):
    """A real ClientHello produced by this machine's OpenSSL, without any network:
    the TLS engine writes into an in-memory buffer instead of a socket."""
    ctx = ssl.create_default_context()
    ctx.set_alpn_protocols(alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=sni)
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass  # waiting for a ServerHello that will never come; we only want the hello
    return outgoing.read()


def dns_raw(txid, flags, qd, an, body):
    return struct.pack("!HHHHHH", txid, flags, qd, an, 0, 0) + body


def app_layer():
    MAIL, FTP_SRV, WEB = "10.0.0.25", "10.0.0.21", "10.0.0.80"
    seqs = {}

    def tcp(src, dst, sport, dport, payload, flags="PA"):
        key = (src, sport, dst, dport)
        seq = seqs.get(key, 1000)
        seqs[key] = seq + len(payload)
        return eth() / IP(src=src, dst=dst) / TCP(sport=sport, dport=dport, flags=flags,
                                                  seq=seq, ack=1, window=64240) / Raw(payload)

    def udp(src, dst, sport, dport, payload):
        return eth() / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)

    pkts = []

    # --- DNS --------------------------------------------------------------
    pkts.append(eth() / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=50001, dport=53)
                / DNS(id=0x1111, rd=1, qd=DNSQR(qname="www.example.com", qtype="A")))
    pkts.append(eth(ROUTER_MAC, CLIENT_MAC) / IP(src=DNS_SRV, dst=CLIENT) / UDP(sport=53, dport=50001)
                / DNS(id=0x1111, qr=1, rd=1, ra=1, qd=DNSQR(qname="www.example.com", qtype="A"),
                      an=[DNSRR(rrname="www.example.com", type="CNAME", rdata="example.com", ttl=60),
                          DNSRR(rrname="example.com", type="A", rdata="93.184.216.34", ttl=60),
                          DNSRR(rrname="example.com", type="A", rdata="93.184.216.35", ttl=60)]))
    pkts.append(eth() / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=50002, dport=53)
                / DNS(id=0x2222, rd=1, qd=DNSQR(qname="nope.invalid", qtype="AAAA")))
    pkts.append(eth(ROUTER_MAC, CLIENT_MAC) / IP(src=DNS_SRV, dst=CLIENT) / UDP(sport=53, dport=50002)
                / DNS(id=0x2222, qr=1, rd=1, ra=1, rcode=3, qd=DNSQR(qname="nope.invalid", qtype="AAAA")))
    # mDNS announcement: a response with answers but no question section
    pkts.append(eth() / IP(src=CLIENT, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
                / DNS(id=0, qr=1, aa=1, qd=[], an=[DNSRR(rrname="_http._tcp.local", type="PTR",
                                                       rdata="Office Printer._http._tcp.local", ttl=120)]))

    # --- HTTP -------------------------------------------------------------
    pkts.append(tcp(CLIENT, WEB, 51000, 80,
                    b"GET /admin HTTP/1.1\r\nHost: intranet.example\r\nUser-Agent: curl/8.5\r\n"
                    b"Authorization: Basic YWxpY2U6aHVudGVyMg==\r\n\r\n"))       # alice:hunter2
    pkts.append(tcp(WEB, CLIENT, 80, 51000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"))
    pkts.append(tcp(CLIENT, WEB, 51001, 8080,
                    b"POST /api/v1/items?id=7 HTTP/1.1\r\nHost: 10.0.0.80:8080\r\n"
                    b"Content-Type: application/json\r\nContent-Length: 2\r\n\r\n{}"))
    pkts.append(tcp(WEB, CLIENT, 8080, 51001, b"HTTP/1.1 404 Not Found\r\n\r\n"))

    # --- TLS --------------------------------------------------------------
    hello = tls_client_hello("www.example.com", ["h2", "http/1.1"])
    pkts.append(tcp(CLIENT, SERVER, 51100, 443, hello))
    # The same kind of hello split across two TCP segments, as happens with
    # large modern hellos: the SNI isn't in the first segment.
    hello2 = tls_client_hello("mail.example.org", ["http/1.1"])
    pkts.append(tcp(CLIENT, SERVER, 51101, 443, hello2[:120]))
    pkts.append(tcp(CLIENT, SERVER, 51101, 443, hello2[120:]))

    # Split again, but this time the cut falls *after* the SNI extension, as
    # with big browser hellos: the hostname is visible in the first piece.
    hello3 = tls_client_hello("shop.example.net", ["h2", "http/1.1"])
    cut = hello3.index(b"shop.example.net") + len(b"shop.example.net") + 4
    pkts.append(tcp(CLIENT, SERVER, 51102, 443, hello3[:cut]))
    pkts.append(tcp(CLIENT, SERVER, 51102, 443, hello3[cut:]))

    # --- Non-ASCII names ---------------------------------------------------
    # Valid UTF-8 (a curly apostrophe) should display as-is...
    pkts.append(eth() / IP(src=CLIENT, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
                / DNS(id=0, qd=[DNSQR(qname="Jake\u2019s Laptop._airplay._tcp.local".encode(), qtype="PTR")]))
    # ...but a right-to-left override (U+202E) must not: it would make this
    # name *display* as "invoice_cod.exe" ("Trojan Source", CVE-2021-42574).
    pkts.append(eth() / IP(src=CLIENT, dst="224.0.0.251", ttl=255) / UDP(sport=5353, dport=5353)
                / DNS(id=0, qd=[DNSQR(qname="invoice_\u202eexe.doc.local".encode(), qtype="A")]))

    # --- Plaintext logins (fake credentials) ----------------------------
    pkts.append(tcp(FTP_SRV, CLIENT, 21, 51200, b"220 ProFTPD Server ready\r\n"))
    pkts.append(tcp(CLIENT, FTP_SRV, 51200, 21, b"USER alice\r\n"))
    pkts.append(tcp(FTP_SRV, CLIENT, 21, 51200, b"331 Password required for alice\r\n"))
    pkts.append(tcp(CLIENT, FTP_SRV, 51200, 21, b"PASS hunter2\r\n"))
    pkts.append(tcp(FTP_SRV, CLIENT, 21, 51200, b"230 User alice logged in\r\n"))
    pkts.append(tcp(CLIENT, FTP_SRV, 51200, 21, b"RETR payroll.xlsx\r\n"))
    pkts.append(tcp(CLIENT, MAIL, 51300, 110, b"USER bob\r\n"))
    pkts.append(tcp(CLIENT, MAIL, 51300, 110, b"PASS pop-secret\r\n"))
    pkts.append(tcp(CLIENT, MAIL, 51301, 143, b'a001 LOGIN carol "correct horse"\r\n'))

    # --- Hostile application data ---------------------------------------
    # DNS name that is a compression pointer to itself (offset 12): infinite loop bait
    pkts.append(udp(DNS_SRV, CLIENT, 53, 50003,
                    dns_raw(0x3333, 0x8180, 1, 0, b"\xc0\x0c" + b"\x00\x01\x00\x01")))
    # Two pointers pointing at each other
    pkts.append(udp(DNS_SRV, CLIENT, 53, 50004,
                    dns_raw(0x4444, 0x8180, 1, 0, b"\xc0\x0e\xc0\x0c" + b"\x00\x01\x00\x01")))
    # Answer count of 50 with no answers present
    pkts.append(udp(DNS_SRV, CLIENT, 53, 50005,
                    dns_raw(0x5555, 0x8180, 0, 50, b"")))
    # Name containing a terminal escape sequence (ESC[2J clears the screen)
    pkts.append(eth() / IP(src=CLIENT, dst=DNS_SRV) / UDP(sport=50006, dport=53)
                / DNS(id=0x6666, rd=1, qd=DNSQR(qname=b"\x1b[2Jgotcha.example.com")))
    # 8 bytes on port 53: too short for a DNS header
    pkts.append(udp(CLIENT, DNS_SRV, 50007, 53, b"\x00\x01\x02\x03\x04\x05\x06\x07"))
    return pkts


if __name__ == "__main__":
    OUT.mkdir(exist_ok=True)
    write(OUT / "basic.pcap", basic(), start=1_700_000_000.0)
    write(OUT / "edge_cases.pcap", edge_cases(), start=1_700_000_100.0)
    write(OUT / "app_layer.pcap", app_layer(), start=1_700_000_200.0)
    print(f"wrote basic.pcap, edge_cases.pcap and app_layer.pcap to {OUT}")
