# sharkWatch

A packet analyzer written in C on top of libpcap. It decodes Ethernet, VLAN,
IPv4, TCP, UDP and ICMP headers by hand, plus the application layer: DNS
lookups, HTTP requests, the hostname inside TLS handshakes, and cleartext
logins.

It also tracks connections, using:

- a flow table built on a keyed hash table
- TCP state tracking
- TCP stream reassembly
- per-connection context

All of these are hardened against memory-exhaustion attacks. Every decoded
field and every conversation is checked against Wireshark.

This is the base for a small network intrusion detector. See the [roadmap](#roadmap).

```
$ ./sharkwatch -r samples/app_layer.pcap
    1   0.000000  192.168.1.10:50001 -> 192.168.1.1:53  UDP len=33  DNS query A www.example.com
    2   0.012500  192.168.1.1:53 -> 192.168.1.10:50001  UDP len=127  DNS response A www.example.com -> 93.184.216.34, 93.184.216.35
    4   0.037500  192.168.1.1:53 -> 192.168.1.10:50002  UDP len=30  DNS response AAAA nope.invalid NXDOMAIN
    6   0.062500  192.168.1.10:51000 -> 10.0.0.80:80  TCP [PSH, ACK] ... len=112  HTTP GET /admin  Host: intranet.example  Basic auth alice / ********  [CLEARTEXT CREDENTIAL]
    9   0.100000  10.0.0.80:8080 -> 192.168.1.10:51001  TCP [PSH, ACK] ... len=26  HTTP 404 Not Found
   10   0.112500  192.168.1.10:51100 -> 93.184.216.34:443  TCP [PSH, ACK] ... len=517  TLS ClientHello SNI=www.example.com ALPN=h2
   14   0.162500  192.168.1.10:51200 -> 10.0.0.21:21  TCP [PSH, ACK] ... len=12  FTP USER alice  [CLEARTEXT CREDENTIAL]
   16   0.187500  192.168.1.10:51200 -> 10.0.0.21:21  TCP [PSH, ACK] ... len=14  FTP PASS ********  [CLEARTEXT CREDENTIAL]
   22   0.262500  192.168.1.1:53 -> 192.168.1.10:50003  UDP len=18  DNS response (0 answers)  [!] DNS name compression loop
   25   0.300000  192.168.1.10:50006 -> 192.168.1.1:53  UDP len=40  DNS query A \x1b[2Jgotcha.example.com
  ...

--- 26 packets, 3187 bytes ---
  IPv4 26  (TCP 16, UDP 10, ICMP 0, other 0; fragments 0)
  ARP 0   IPv6 0   other L3 0
  DNS 3 queries / 6 responses   HTTP 2 requests / 2 responses
  TLS 2 ClientHellos (1 with SNI)
  malformed/truncated 4

  !! 6 cleartext credential(s) seen:
     frame 6      192.168.1.10 -> 10.0.0.80:80  HTTP Basic login: alice / ********
     frame 14     192.168.1.10 -> 10.0.0.21:21  FTP username: alice
     frame 16     192.168.1.10 -> 10.0.0.21:21  FTP password: ********
     ...
```

Connection tracking rebuilds messages split across TCP segments and ties
packets together:

```
$ ./sharkwatch -r samples/flows.pcap -F 6
    7  ... 192.168.1.10:52001 -> 93.184.216.34:443  TCP ... TLS ClientHello SNI=reassembled.example.com ALPN=h2 (reassembled from 3 segments)
   15  ... 192.168.1.10:52002 -> 93.184.216.34:443  TCP ... TLS ClientHello SNI=attacker.example.net  [*] overlapping TCP segment with different data (first copy kept)
   16  ... 192.168.1.10:52002 -> 93.184.216.34:443  TCP ... TLS ClientHello SNI=innocent.example.com ALPN=h2 (reassembled from 2 segments)
   34  ... 192.168.1.10:52004 -> 10.0.0.21:21  TCP ... FTP PASS ********  (user alice)  [CLEARTEXT CREDENTIAL]
   43  ... 10.0.0.80:80 -> 192.168.1.10:52005  TCP ... HTTP 200 OK  (answers GET /index.html)

--- Top 6 conversations by bytes (of 10) ---
  proto client                   server                 packets      bytes  duration  state        about
  TCP   192.168.1.10:52001    -> 93.184.216.34:443           10     1.1 KB     0.11s  closed       reassembled.example.com
  TCP   192.168.1.10:52002    -> 93.184.216.34:443            9     1.1 KB     0.10s  closed       innocent.example.com
  TCP   192.168.1.10:52003    -> 93.184.216.34:443            8      949 B     0.09s  closed       wraparound.example.com
  TCP   192.168.1.10:52005    -> 10.0.0.80:80                10      720 B     0.11s  closed       shop.example
  TCP   192.168.1.10:52004    -> 10.0.0.21:21                11      667 B     0.12s  closed       FTP login: alice
  TCP   192.168.1.10:52006    -> 10.0.0.80:80                 7      421 B     0.07s  closed       shop.example
  ...
  Flows: 9 TCP (7 handshakes, 1 mid-stream, 1 reset, 1 port reuse), 1 UDP; peak 9 active
  Reassembly: 3 split ClientHello(s) rebuilt, 2 retransmission(s), 1 overlap conflict(s)
```

(All credentials in the sample captures are fake.)

## Build

Requires a C11 compiler and libpcap headers. Runs on Linux, macOS, and WSL.

```sh
# Debian/Ubuntu/WSL           # macOS (libpcap ships with the OS)
sudo apt install build-essential libpcap-dev
make
```

## Usage

```
sharkwatch (-r FILE | -i IFACE) [options] [BPF filter]

  -r FILE     read packets from a pcap/pcapng file
  -i IFACE    capture live from an interface (needs root/CAP_NET_RAW)
  -c N        stop after N packets
  -s SNAPLEN  bytes to capture per packet (default 65535)
  -v          verbose: add an L2/L3 detail line per packet
  -T          tab-separated fields instead (for scripts / diffing)
  -P          show cleartext passwords instead of ********
  -F N        after the packets, list the top N conversations by bytes
              (0 = all; with -T, as tab-separated "flow" rows)
  -m N        track at most N connections at once (default 65536)
```

Examples:

```sh
./sharkwatch -r capture.pcapng
./sharkwatch -r capture.pcapng tcp port 443          # BPF filter, same syntax as tcpdump
./sharkwatch -r capture.pcapng udp port 53           # every DNS lookup
./sharkwatch -r capture.pcapng > /dev/null           # summary only, incl. credentials seen
./sharkwatch -r capture.pcapng -F 10 | tail -20      # top 10 conversations + summary
sudo ./sharkwatch -i eth0 -c 100 -v
sudo ./sharkwatch -i any not port 22                 # Linux "any" pseudo-interface
```

Live capture stops cleanly on Ctrl-C and prints a summary including kernel drop counts.

## What it decodes

| Layer | Protocols |
|---|---|
| Link | Ethernet II, 802.1Q / Q-in-Q VLAN tags, Linux cooked capture v1/v2 |
| Network | IPv4 (options, fragments). ARP and IPv6 are labelled. |
| Transport | TCP (flags, seq/ack, options length), UDP, ICMP |
| Application | **DNS / mDNS / LLMNR**: question, answer count, A records, error codes |
| | **HTTP/1.x**: method, URI, Host, status; detected by content on any port |
| | **TLS**: Server Name Indication (SNI) and ALPN from the ClientHello |
| | **Cleartext logins**: FTP and POP3 `USER`/`PASS`, IMAP `LOGIN`, HTTP Basic auth |
| Connections | TCP/UDP flows, TCP state, retransmissions, stream reassembly of split ClientHellos, FTP USER+PASS pairing, HTTP response-to-request matching |

## How it works

```
pcap_loop ─▶ decode_packet() ─▶ packet_t ─▶ print_packet() / print_packet_tsv()
              │
              ├─ link layer:   Ethernet II (+802.1Q / Q-in-Q), Linux cooked v1/v2
              ├─ network:      IPv4 (options, fragments)
              ├─ transport:    TCP, UDP, ICMP                        (decode.c)
              └─ application:  DNS, HTTP, TLS ClientHello, FTP/POP3/IMAP  (app.c)
                    │
                    ▼
              flow_update()   connection tracking + reassembly        (flow.c)
```

Decoding and printing are separate. The decoders fill a `packet_t` struct and
never print anything. The flow tracker then enriches it, attaching a reassembled
hello, a paired login, or the request a response answers. Later stages
(detection) consume `packet_t` and the flow table without touching raw bytes.

### Header parsing

- **No pointer casts onto packet memory.** The IPv4 header starts 14 bytes into
  an Ethernet frame, so it isn't 4-byte aligned, and reading a misaligned
  `uint32_t` through a cast pointer is undefined behavior in C. Each header is
  `memcpy`'d into an aligned local struct instead. `_Static_assert`s pin the
  struct sizes to the wire format.
- **Every read is bounds-checked against the captured length.** Captures are
  untrusted input. A short or lying header produces an error message, never an
  out-of-bounds read.
- **The IP total length, not the frame length, decides where a datagram ends.**
  Ethernet pads small frames to 60 bytes, and those trailing zeros are not
  payload. Snaplen can also cut a frame short, so `packet_t` records both the
  on-the-wire payload length and how much of it was actually captured.
- **Fragments are handled correctly.** Only the first fragment carries a
  TCP/UDP header. Later fragments are reported as continuation data, not
  misparsed as a transport header.

### Application layer: treating payloads as hostile

Whoever sends a packet controls every byte of its payload, so `app.c` assumes
the worst:

- **DNS compression loops are capped.** DNS names can contain "pointers" back
  to earlier parts of the message. A malicious packet can point a name at
  itself, and a naive decoder then loops forever. sharkwatch limits the number
  of pointer jumps and the total name length, and reports
  `DNS name compression loop` instead of hanging. (Wireshark gives no warning at
  all on the self-pointing case in `samples/app_layer.pcap`.)
- **Every extracted string is sanitized before printing.** A DNS name or HTTP
  header can contain terminal escape codes. `ESC[2J`, for example, clears the
  screen of whoever is reading the output. Unsafe bytes are shown as `\xNN`
  escapes, so `\x1b[2Jgotcha.example.com` is displayed as text instead of
  being executed by the terminal.
- **Unicode is allowed, but not the dangerous parts.** Real device names aren't
  ASCII (`Jake’s Laptop` has a 3-byte curly apostrophe), so valid UTF-8 is
  shown as-is. Still escaped:
  - invalid or overlong UTF-8
  - C1 control characters
  - invisible characters
  - bidi overrides like U+202E, the "Trojan Source" trick
    ([CVE-2021-42574](https://trojansource.codes/)) that can make
    `invoice_` + U+202E + `exe.doc` *display* as `invoice_cod.exe`

  Fuzzing with 20,000 hostile names confirmed that the output is always valid
  UTF-8 with no control, invisible or bidi characters.
- **Fixed-size buffers, length-bounded copies.** No string is assumed to be
  NUL-terminated, and every copy is truncated to its buffer.
- **Passwords are masked by default.** Output tends to end up in tickets,
  chats and screenshots, so passwords print as `********` unless you pass `-P`.

### Why HTTPS still leaks hostnames

TLS encrypts everything after the handshake, but the client's first message
(the ClientHello) is plaintext. It usually carries the **Server Name
Indication**, the hostname the client wants, so the server knows which
certificate to send. That's why sharkwatch can show `SNI=pypi.org` for a
connection whose contents it can't read. Encrypted Client Hello (ECH) closes
this gap where it's deployed.

A TCP segment can hold several TLS records, so sharkwatch doesn't assume the
hello is the first byte. When a TLS 1.3 server rejects the client's key type
with a **HelloRetryRequest**, the client sends a second ClientHello, and in
"middlebox compatibility mode" it puts a dummy ChangeCipherSpec record in
front of it, in the same segment. sharkwatch skips those records and labels
the result `(retry after HelloRetryRequest)`. Steam's client was caught doing
this in a real home capture, which is how this case was found.

### Connection tracking (`flow.c`)

Packets are grouped into **flows**: one TCP connection or UDP conversation,
with both directions mapped to the same entry.

- **Hash table with a secret key.** Flows live in a chained hash table. A
  predictable hash function lets an attacker pick addresses and ports that all
  land in one bucket, turning every lookup into a linear scan ("hash
  flooding"). sharkwatch hashes with **SipHash-2-4** under a random per-run key,
  the same defense Python, Rust and the Linux kernel use.
- **TCP state.** Handshakes, FIN/RST teardown, connections the capture joined
  mid-stream, and **port reuse** are tracked. A fresh SYN on a closed
  connection starts a new flow, as in Wireshark.
- **Stream-head reassembly.** Large modern ClientHellos (post-quantum key shares)
  don't fit in one segment. When the first segment's message is incomplete,
  sharkwatch buffers the start of that stream (up to 16 KB) and places each
  segment by sequence number, so out-of-order delivery, duplicates and
  sequence-number wraparound past 2³² all work. The decoded result is attached
  to the segment that completes it, labelled `(reassembled from N segments)`.
  Wireshark reports it the same way.
- **Overlapping segments with conflicting data are flagged.** Sending the same
  sequence numbers twice with *different* bytes is a classic IDS-evasion
  technique (Ptacek & Newsham, 1998): the IDS and the target host may each
  keep a different copy. sharkwatch keeps the first copy and marks the packet
  `[*] overlapping TCP segment with different data`. In the sample, the
  conflicting segment by itself claims `attacker.example.net`, while the
  reassembled stream says `innocent.example.com`.
- **Retransmissions** (data at or below sequence numbers already seen) are
  labelled and not counted twice, so a retransmitted login doesn't show up as
  two credentials.
- **Per-connection context.** An FTP/POP3 `PASS` is paired with the same
  connection's `USER`, and an HTTP response is matched with the request it
  answers.

### Resource limits: the IDS as a target

An IDS has to store state for traffic an attacker controls, so an attacker can
try to exhaust its memory and blind it. Every resource is capped:

| Resource | Limit | When exceeded |
|---|---|---|
| Tracked flows | 65,536 (`-m`) | least-recently-used flow evicted (O(1) via an LRU list) |
| Idle flows | 300 s without a packet | expired |
| Reassembly per stream | first 16 KB / 64 segments, and only when a message is split | stop buffering that stream |
| Reassembly overall | 64 MB across all flows | new reassemblies refused, counted |

`tests/stress_flows.py` attacks these limits directly:

```
SYN flood, 500,000 SYNs, cap  65536: peak 65536 flows, 434464 evicted, max RSS 38 MB  OK
SYN flood, 500,000 SYNs, cap   1000: peak 1000 flows, 499000 evicted, max RSS 4 MB  OK
Reassembly bomb, 20,000 stalled hellos: 16360 reassemblies refused by the 64 MB budget, max RSS 76 MB  OK
```

Without the reassembly budget, the 20,000 half-finished handshakes would pin
about 360 MB.

### Known limits

- Only the **first message** of each stream direction is reassembled (that's
  where the TLS hostname is). An HTTP request whose headers span segments is
  decoded from its first segment only.
- For connections the capture joined **mid-stream**, reassembly starts at the
  first data seen, so a split message that began before the capture can't be
  rebuilt.
- DNS over HTTPS and QUIC (HTTP/3) are encrypted, so their lookups and hostnames
  aren't visible here.

## Testing

### Verified against Wireshark

`make test` runs both `sharkwatch -T` and `tshark -T fields` on each sample
capture and compares, packet by packet:

- **Headers:** IPs, protocol, TTL, ports, TCP flags/seq/ack/payload length, UDP
  length, ICMP type/code
- **DNS:** question name and type, response flag, answer count, first A record
- **HTTP:** method, URI, Host, status code, Basic auth
- **TLS:** SNI, ALPN, compared against Wireshark's own TCP reassembly, so
  split hellos are checked too
- **FTP/POP3:** command and argument
- **Conversations:** every TCP/UDP flow's packet and byte counts in each
  direction, sharkwatch's flow table against Wireshark's `tcp.stream` /
  `udp.stream`

```
$ make test
== samples/app_layer.pcap: 31 packets
  2 TLS ClientHello(s) split across segments; 2 reassembled and compared
  427 fields compared, 0 mismatches
  17 conversations compared, 0 mismatches
== samples/basic.pcap: 15 packets
  210 fields compared, 0 mismatches
  2 conversations compared, 0 mismatches
== samples/edge_cases.pcap: 12 packets
  92 fields compared, 0 mismatches
  5 conversations compared, 0 mismatches
== samples/flows.pcap: 68 packets
  5 TLS ClientHello(s) split across segments; 3 reassembled and compared
  1040 fields compared, 0 mismatches
  10 conversations compared, 0 mismatches

PASS
```

On real traffic, the comparison passes with 0 mismatches on:

- **An 11,000-packet home Wi-Fi capture** recorded in Wireshark on Windows
  (139,762 fields).
- **A 4,000-packet capture** made to exercise Stage 3 on real services: DNS,
  NXDOMAIN, HTTP Basic auth, FTP, HTTPS from curl and a browser, and Steam's
  TLS 1.3 HelloRetryRequest.
- **8,000+ packets of live traffic** covering real TLS handshakes from curl,
  OpenSSL and Python, a forced HelloRetryRequest, a TLS 1.2 handshake, real DNS
  answers, and HTTP with Basic auth. Their conversations match Wireshark's too.

You can run it on any capture of your own:
`python3 tests/verify_against_tshark.py ./sharkwatch your.pcap`.

TLS fields are compared on client-to-server packets only. sharkwatch decodes
the ClientHello, while in TLS 1.2 tshark also reports the server's chosen ALPN
from the ServerHello.

The verifier works with both Wireshark 4.2 and 4.6, which spell escaped
characters differently (`\033` vs `\\x1b` vs `\u202E`). It normalizes those
spellings so only real differences count.

The test also has to be able to fail. Planting bugs confirms that it does: a
missing `ntohs()` on a port, an SNI copied one byte short, and a skipped DNS
answer are each caught immediately.

### Property-based reassembly test

`tests/reassembly_property.py` builds thousands of connections, each carrying
a real ClientHello with a unique hostname. It then mangles delivery the way
real networks do:

- cuts each hello into 1-6 segments at random points
- shuffles the segments
- duplicates some of them
- starts some sequence numbers just below 2³² so they wrap mid-hello

The property: every connection yields exactly one decoded hello, with the
right hostname. It runs 10,000 connections across 5 seeds with 0 failures.

Its first run found two real bugs:

- **A tiny first segment made sharkwatch give up on the stream.** A first
  piece under 6 bytes is too short to recognize as TLS.
- **Retransmitted hellos were counted twice.**

Both are fixed, and the test guards them. `make check` runs this test and the
stress tests on top of `make test`.

### Sample captures

`scripts/make_samples.py` (scapy) generates the captures in `samples/`:

- **`basic.pcap`**: a DNS lookup, a full TCP handshake, an HTTP exchange and
  teardown, a ping, and ARP.
- **`edge_cases.pcap`**: packets designed to break a careless header parser:
  - Ethernet padding
  - a VLAN tag
  - IP and TCP options
  - a fragmented datagram
  - an ICMP error quoting another packet
  - IPv6
  - a snaplen-truncated frame
  - a bogus IHL
  - a 10-byte runt frame
- **`app_layer.pcap`**: application traffic:
  - DNS with CNAME and multiple A records, an NXDOMAIN, and an mDNS announcement
  - HTTP with Basic auth, and HTTP on port 8080
  - real OpenSSL ClientHellos, including one split across two segments
  - FTP, POP3 and IMAP logins
  - a ClientHello split *after* its SNI, as large browser hellos are
  - a retried ClientHello behind a ChangeCipherSpec record (HelloRetryRequest)
  - mDNS names with a curly apostrophe and a bidi-override character
  - hostile DNS: self-pointing and mutually-pointing compression loops, a lying
    answer count, a terminal escape sequence in a name, and a runt header
- **`flows.pcap`**: connection tracking:
  - a hello in 3 segments delivered out of order with a duplicate
  - an overlapping segment with conflicting data
  - sequence-number wraparound
  - FTP login pairing and HTTP keep-alive
  - port reuse, a mid-stream connection, a reset, and a UDP conversation

### Fuzzing

`make sanitize` builds with AddressSanitizer (including leak detection) and
UndefinedBehaviorSanitizer. That build was run against about 270,000 hostile
packets:

- **20,000 aimed at the header parsers:** bit flips, truncations, bad header
  lengths, and wire lengths that don't match.
- **50,000 aimed at the application parsers:** corrupted DNS/TLS/HTTP payloads,
  forged length fields and compression pointers.
- **200,000 chaotic TCP/UDP packets aimed at the flow tracker:**
  - colliding ports
  - random flags and sequence numbers
  - RSTs in the middle of reassembly
  - partial and CCS-prefixed hellos
  - idle gaps that trigger expiry
  - table caps as small as 1 flow, to force constant eviction

Result: no memory errors, no leaks, no undefined behavior, and no raw control
characters in the output from hostile input.

## Roadmap

- [x] **Stage 0**: open live/offline captures with libpcap
- [x] **Stage 1**: Ethernet, VLAN, Linux cooked and IPv4 decoding
- [x] **Stage 2**: TCP / UDP / ICMP decoding, tshark verification, fuzzing
- [x] **Stage 3**: application layer: DNS, HTTP, TLS SNI, cleartext credentials
- [x] **Stage 4**: connection tracking: keyed hash table, TCP state, stream reassembly, resource limits
- [ ] **Stage 5**: detection: port scans, SYN floods, ARP spoofing

## Layout

```
include/proto.h    on-the-wire header structs and constants
include/decode.h   packet_t, the decoded representation
include/app.h      application-layer fields (DNS, HTTP, TLS, credentials)
include/flow.h     flow table, TCP state, reassembly, resource limits
src/decode.c       link / network / transport decoders
src/app.c          application-layer decoders
src/flow.c         connection tracking (SipHash table, LRU, reassembly)
src/print.c        human-readable and TSV output
src/main.c         CLI, capture loop, stats
scripts/           sample capture generator
samples/           test captures
tests/             tshark comparison, reassembly property test, stress tests
```
