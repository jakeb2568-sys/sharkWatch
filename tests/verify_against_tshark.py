#!/usr/bin/env python3
"""
Check sharkwatch's decoding field-by-field against Wireshark's (tshark).

    python3 tests/verify_against_tshark.py ./sharkwatch samples/*.pcap

For every packet, runs `sharkwatch -T -P` and `tshark -T fields` on the same
file and compares:
  - headers: IPs, protocol, TTL, ports, TCP flags/seq/ack/len, UDP length,
    ICMP type/code
  - application layer: DNS question/answers, HTTP method/URI/Host/status/Basic
    auth, TLS SNI/ALPN, FTP and POP3 commands
  - connections: every TCP/UDP conversation's packet and byte counts in each
    direction (sharkwatch's flow table vs tshark's tcp.stream / udp.stream)
Exits non-zero on any mismatch.
"""
import re
import subprocess
import sys

COLUMNS = ["frame", "ip.src", "ip.dst", "ip.proto", "ip.ttl", "srcport", "dstport",
           "tcp.flags", "tcp.seq_raw", "tcp.ack_raw", "tcp.len", "udp.length",
           "icmp.type", "icmp.code",
           "dns.qry.name", "dns.qry.type", "dns.flags.response", "dns.count.answers", "dns.a",
           "http.method", "http.uri", "http.host", "http.code", "http.authbasic",
           "tls.sni", "tls.alpn", "tls.state", "cmd", "cmd.arg", "tcp.retrans"]
L4_COLUMNS = COLUMNS[5:14]
DNS_COLUMNS = COLUMNS[14:19]
HTTP_COLUMNS = COLUMNS[19:24]
TLS_COLUMNS = COLUMNS[24:26]      # tls.state is ours only; not compared
CMD_COLUMNS = COLUMNS[27:29]

DNS_PORTS = {"53", "5353", "5355"}
HTTP_PORTS = {"80", "8080"}      # ports tshark decodes as HTTP by default
TLS_PORTS = {"443"}

# Our column name -> tshark field. Ports and commands are merged below.
TSHARK_FIELDS = {
    "frame": "frame.number", "ip.src": "ip.src", "ip.dst": "ip.dst",
    "ip.proto": "ip.proto", "ip.ttl": "ip.ttl",
    "tcp.flags": "tcp.flags", "tcp.seq_raw": "tcp.seq_raw", "tcp.ack_raw": "tcp.ack_raw",
    "tcp.len": "tcp.len", "udp.length": "udp.length",
    "icmp.type": "icmp.type", "icmp.code": "icmp.code",
    "dns.qry.name": "dns.qry.name", "dns.qry.type": "dns.qry.type",
    "dns.flags.response": "dns.flags.response", "dns.count.answers": "dns.count.answers",
    "dns.a": "dns.a",
    "http.method": "http.request.method", "http.uri": "http.request.uri",
    "http.host": "http.host", "http.code": "http.response.code",
    "http.authbasic": "http.authbasic",
    "tls.sni": "tls.handshake.extensions_server_name",
    "tls.alpn": "tls.handshake.extensions_alpn_str",
}
EXTRA_FIELDS = ["tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
                "ftp.request.command", "ftp.request.arg",
                "pop.request.command", "pop.request.parameter",
                "tcp.stream", "udp.stream", "frame.len",
                "_ws.expert.message"]
FIELD_LIST = list(TSHARK_FIELDS.values()) + EXTRA_FIELDS


C_ESCAPES = {"a": 7, "b": 8, "t": 9, "n": 10, "v": 11, "f": 12, "r": 13}


def tshark_escapes_to_hex(v):
    """Wireshark shows unprintable bytes as escapes, and the spelling depends on
    the version: 4.2 prints ESC as \\033; 4.6 prints \\x1b and then escapes the
    backslash itself in -T fields output (\\\\x1b). We print \\x1b. Convert
    theirs to ours so only real differences count."""
    v = v.replace("\\\\", "\\")                     # 4.6: \\x1b -> \x1b
    # Invisible/bidi characters: Wireshark writes \u202E, we write the UTF-8
    # bytes \xe2\x80\xae. Same character, both refuse to display it raw.
    v = re.sub(r"\\u([0-9A-Fa-f]{4})",
               lambda m: "".join("\\x%02x" % b for b in chr(int(m.group(1), 16)).encode()), v)
    v = re.sub(r"\\([0-7]{3})", lambda m: "\\x%02x" % int(m.group(1), 8), v)
    return re.sub(r"\\([abtnvfr])", lambda m: "\\x%02x" % C_ESCAPES[m.group(1)], v)


# Characters sharkwatch deliberately escapes even though they're valid UTF-8
# (C1 controls, invisible and bidi characters). In case a Wireshark version
# shows one raw, escape it the way sharkwatch does before comparing.
def _unsafe_char(ch):
    cp = ord(ch)
    return (0x80 <= cp <= 0x9F or 0x200B <= cp <= 0x200F or 0x2028 <= cp <= 0x202E or
            0x2066 <= cp <= 0x2069 or cp in (0x061C, 0xFEFF))


def escape_like_sharkwatch(v):
    return "".join("".join("\\x%02x" % b for b in ch.encode()) if _unsafe_char(ch) else ch
                   for ch in v)


def norm(v):
    """'0x0012' == '18', 'True' == '1'."""
    v = v.strip()
    if v.startswith("0x") and re.fullmatch(r"0x[0-9a-fA-F]+", v):
        return str(int(v, 16))
    return {"True": "1", "False": "0"}.get(v, v)


def run_sharkwatch(binary, pcap):
    # -P: compare real passwords, not the ******** mask; -F 0: list all flows
    out = subprocess.run([binary, "-T", "-P", "-F", "0", "-r", pcap],
                         capture_output=True, text=True, check=True).stdout
    rows, flows = {}, []
    for line in out.splitlines():
        parts = line.split("\t")
        if parts[0] == "flow":
            # flow proto cli_ip cli_port srv_ip srv_port pkts0 bytes0 pkts1 bytes1 ...
            flows.append(parts[1:10])
            continue
        row = dict(zip(COLUMNS, map(norm, parts[:len(COLUMNS)])))
        row["error"] = parts[len(COLUMNS)] if len(parts) > len(COLUMNS) else ""
        rows[row["frame"]] = row
    return rows, flows


def run_tshark(pcap):
    cmd = ["tshark", "-r", pcap,
           "-o", "ip.defragment:FALSE",                 # we don't reassemble IP...
           "-o", "tcp.desegment_tcp_streams:FALSE",     # ...or TCP streams (yet)
           "-T", "fields", "-E", "separator=/t",
           "-E", "occurrence=f"]                        # first occurrence of each field
    for f in FIELD_LIST:
        cmd += ["-e", f]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    rows = {}
    for line in out.splitlines():
        p = dict(zip(FIELD_LIST, line.split("\t")))
        row = {ours: norm(escape_like_sharkwatch(tshark_escapes_to_hex(p.get(f, ""))))
               for ours, f in TSHARK_FIELDS.items()}
        row["srcport"] = p["tcp.srcport"] or p["udp.srcport"]
        row["dstport"] = p["tcp.dstport"] or p["udp.dstport"]
        row["cmd"] = p["ftp.request.command"] or p["pop.request.command"]
        row["cmd.arg"] = p["ftp.request.arg"] or p["pop.request.parameter"]
        row["expert"] = p.get("_ws.expert.message", "")
        row["tcp.stream"], row["udp.stream"] = p["tcp.stream"], p["udp.stream"]
        row["frame.len"] = p["frame.len"]
        rows[row["frame"]] = row
    return rows


def run_tshark_tls(pcap):
    """TLS fields with TCP reassembly ON, like sharkwatch's flow tracker: a
    ClientHello split over several segments is reported on the segment that
    completes it."""
    cmd = ["tshark", "-r", pcap, "-o", "ip.defragment:FALSE",
           "-o", "tcp.reassemble_out_of_order:TRUE",   # sharkwatch places segments by seq too
           "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f",
           "-e", "frame.number", "-e", TSHARK_FIELDS["tls.sni"], "-e", TSHARK_FIELDS["tls.alpn"]]
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    tls = {}
    for line in out.splitlines():
        f, sni, alpn = (line.split("\t") + ["", "", ""])[:3]
        tls[f] = {"tls.sni": norm(escape_like_sharkwatch(tshark_escapes_to_hex(sni))),
                  "tls.alpn": norm(alpn)}
    return tls


def conversations_tshark(ours, theirs):
    """Group tshark's packets by tcp.stream / udp.stream. Only packets that
    sharkwatch decoded down to TCP/UDP ports count (not ICMP errors quoting a
    UDP header, not later IP fragments, not packets truncated mid-header)."""
    conv = {}
    for frame, w in ours.items():
        if w["ip.proto"] not in ("6", "17") or not w["srcport"]:
            continue
        t = theirs[frame]
        sid = t["tcp.stream"] if w["ip.proto"] == "6" else t["udp.stream"]
        if sid == "":
            continue
        c = conv.setdefault((w["ip.proto"], sid), {})
        ep = (w["ip.src"], w["srcport"])
        pk, by = c.get(ep, (0, 0))
        c[ep] = (pk + 1, by + int(t["frame.len"]))
    return conv


def conv_signature(proto, eps):
    """Order-independent description of one conversation."""
    return (proto,) + tuple(sorted((f"{ip}:{port}", pk, by) for (ip, port), (pk, by) in eps.items()))


def compare_flows(ours_rows, our_flows, theirs):
    proto_num = {"TCP": "6", "UDP": "17"}
    mine = []
    for proto, cip, cport, sip, sport, p0, b0, p1, b1 in our_flows:
        eps = {}                                  # endpoints that actually sent something
        if int(p0):
            eps[(cip, cport)] = (int(p0), int(b0))
        if int(p1):
            eps[(sip, sport)] = (int(p1), int(b1))
        mine.append(conv_signature(proto_num[proto], eps))
    theirs_sig = [conv_signature(proto, eps)
                  for (proto, _), eps in conversations_tshark(ours_rows, theirs).items()]
    missing = sorted(set(theirs_sig) - set(mine))
    extra = sorted(set(mine) - set(theirs_sig))
    if len(mine) != len(theirs_sig) and not missing and not extra:
        missing = ["(same conversations, different counts of duplicates)"]
    for sig in missing[:5]:
        print(f"  conversation only in tshark:     {sig}")
    for sig in extra[:5]:
        print(f"  conversation only in sharkwatch: {sig}")
    print(f"  {len(mine)} conversations compared, {len(missing) + len(extra)} mismatches")
    return len(missing) + len(extra)


def columns_to_check(w):
    cols = [c for c in COLUMNS[1:14]]
    if not w["ip.src"]:
        return [c for c in cols if c not in L4_COLUMNS]   # ARP, IPv6: L2 only for now
    if w["ip.proto"] == "1":
        # For ICMP errors tshark also dissects the quoted inner packet and
        # reports *its* ports; those aren't fields of this packet.
        return [c for c in cols if c not in L4_COLUMNS[:7]]

    ports = {w["srcport"], w["dstport"]}
    if w["ip.proto"] == "17" and ports & DNS_PORTS:
        cols += DNS_COLUMNS
    if w["ip.proto"] == "6":
        if ports & HTTP_PORTS:
            cols += HTTP_COLUMNS
            if not w["http.method"]:
                # Newer Wireshark (4.6+) matches each response to its request
                # and repeats the request's URI on the response packet. We
                # decode one packet at a time (until Stage 4), so only compare
                # the URI on the request itself.
                cols.remove("http.uri")
        if w["dstport"] in TLS_PORTS:
            # Client -> server only: we decode the ClientHello. In TLS 1.2 the
            # server's reply (ServerHello) also carries the chosen ALPN in
            # plaintext, which tshark reports and we deliberately don't.
            cols += TLS_COLUMNS
        if w["dstport"] in ("21", "110"):
            cols += CMD_COLUMNS
    return cols


def compare(binary, pcap):
    (ours, our_flows), theirs, tls = run_sharkwatch(binary, pcap), run_tshark(pcap), run_tshark_tls(pcap)
    mismatches = checked = split_hellos = reassembled = 0
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
        cols = columns_to_check(w)
        if "tls.sni" in cols:
            # TLS is compared with tshark's *reassembled* view: a split hello
            # is reported on the segment that completes it, by both tools.
            # The first piece (tls.state=partial) is our own early look at
            # it; tshark shows nothing there, so it isn't compared.
            t = dict(t, **tls.get(frame, {"tls.sni": "", "tls.alpn": ""}))
            if w["tls.state"] == "partial":
                split_hellos += 1
                cols = [c for c in cols if c not in TLS_COLUMNS]
            elif w["tls.state"] == "reassembled":
                reassembled += 1
        for c in cols:
            checked += 1
            if w[c] != t[c]:
                mismatches += 1
                print(f"  frame {frame:>3}: {c:<18} sharkwatch={w[c]!r:<24} tshark={t[c]!r}")

    if split_hellos:
        print(f"  {split_hellos} TLS ClientHello(s) split across segments; "
              f"{reassembled} reassembled and compared")
    print(f"  {checked} fields compared, {mismatches} mismatches")
    return mismatches + compare_flows(ours, our_flows, theirs)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    bad = sum(compare(sys.argv[1], p) for p in sys.argv[2:])
    print("\nPASS" if bad == 0 else f"\nFAIL: {bad} mismatches")
    sys.exit(1 if bad else 0)
