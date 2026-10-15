# sharkWatch

A packet analyzer written in C on top of libpcap. It decodes Ethernet, VLAN,
IPv4, TCP, UDP and ICMP headers by hand, plus the application layer: DNS
lookups, HTTP requests, the hostname inside TLS handshakes, and cleartext
logins. Every field is checked against Wireshark's own dissectors.

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
```

Examples:

```sh
./sharkwatch -r capture.pcapng
./sharkwatch -r capture.pcapng tcp port 443          # BPF filter, same syntax as tcpdump
./sharkwatch -r capture.pcapng udp port 53           # every DNS lookup
./sharkwatch -r capture.pcapng > /dev/null           # summary only, incl. credentials seen
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

## How it works

```
pcap_loop ─▶ decode_packet() ─▶ packet_t ─▶ print_packet() / print_packet_tsv()
              │
              ├─ link layer:   Ethernet II (+802.1Q / Q-in-Q), Linux cooked v1/v2
              ├─ network:      IPv4 (options, fragments)
              ├─ transport:    TCP, UDP, ICMP                        (decode.c)
              └─ application:  DNS, HTTP, TLS ClientHello, FTP/POP3/IMAP  (app.c)
```

Decoding and printing are separate. The decoders fill a `packet_t` struct and
never print anything, so later stages (flow tracking, detection) can use
decoded packets without touching raw bytes.

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

### Known limits

- **One packet at a time.** A message split across several TCP segments is
  decoded only from the segment that contains its start. This matters for
  large modern ClientHellos (post-quantum key shares push them past one segment),
  which are reported as `(continues in next segment)` when the SNI isn't in the
  first part. TCP stream reassembly arrives with flow tracking in Stage 4.
- FTP/POP3 usernames and passwords arrive in separate packets and are listed
  separately. Pairing them per connection is also a Stage 4 job.
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
- **TLS:** SNI, ALPN
- **FTP/POP3:** command and argument

```
$ make test
== samples/app_layer.pcap: 26 packets
  frame  22: sharkwatch flagged "DNS name compression loop"  | tshark: (no warning)
  frame  23: sharkwatch flagged "DNS name compression loop"  | tshark: Extraneous data
  frame  24: sharkwatch flagged "truncated DNS name"  | tshark: Malformed Packet (Exception occurred)
  frame  26: sharkwatch flagged "truncated DNS header"  | tshark: Malformed Packet (Exception occurred)
  352 fields compared, 0 mismatches
== samples/basic.pcap: 15 packets
  218 fields compared, 0 mismatches
== samples/edge_cases.pcap: 12 packets
  ...
  92 fields compared, 0 mismatches

PASS
```

On real traffic, the comparison passes with 0 mismatches on:

- **An 11,000-packet home Wi-Fi capture** recorded in Wireshark on Windows
  (139,762 fields).
- **8,000+ packets of live traffic** covering real TLS handshakes from curl,
  OpenSSL and Python, real DNS answers, and HTTP with Basic auth (122,867 fields).

You can run it on any capture of your own:
`python3 tests/verify_against_tshark.py ./sharkwatch your.pcap`.

TLS fields are compared on client-to-server packets only. sharkwatch decodes
the ClientHello, while in TLS 1.2 tshark also reports the server's chosen ALPN
from the ServerHello. ClientHellos split across TCP segments (common with
browsers) are counted and reported separately rather than compared. Without stream reassembly, sharkwatch
and Wireshark recover different parts of the pieces, so there's nothing
meaningful to diff until Stage 4.

The verifier works with both Wireshark 4.2 and 4.6, which spell escaped
characters differently (`\033` vs `\\x1b` vs `\u202E`). It normalizes those
spellings so only real differences count.

The test also has to be able to fail. Planting bugs confirms that it does: a
missing `ntohs()` on a port, an SNI copied one byte short, and a skipped DNS
answer are each caught immediately.

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

### Fuzzing

`make sanitize` builds with AddressSanitizer and UndefinedBehaviorSanitizer.
That build was run against about 70,000 randomly corrupted packets:

- **20,000 aimed at the header parsers:** bit flips, truncations, bad header
  lengths, and wire lengths that don't match.
- **50,000 aimed at the application parsers:** corrupted DNS/TLS/HTTP payloads,
  forged length fields and compression pointers.

Result: no memory errors, no undefined behavior, and no raw control characters
in 60,000+ lines of output from hostile input.

## Roadmap

- [x] **Stage 0**: open live/offline captures with libpcap
- [x] **Stage 1**: Ethernet, VLAN, Linux cooked and IPv4 decoding
- [x] **Stage 2**: TCP / UDP / ICMP decoding, tshark verification, fuzzing
- [x] **Stage 3**: application layer: DNS, HTTP, TLS SNI, cleartext credentials
- [ ] **Stage 4**: per-flow state tracking (hash table of connections), TCP reassembly
- [ ] **Stage 5**: detection: port scans, SYN floods, ARP spoofing

## Layout

```
include/proto.h    on-the-wire header structs and constants
include/decode.h   packet_t, the decoded representation
include/app.h      application-layer fields (DNS, HTTP, TLS, credentials)
src/decode.c       link / network / transport decoders
src/app.c          application-layer decoders
src/print.c        human-readable and TSV output
src/main.c         CLI, capture loop, stats
scripts/           sample capture generator
samples/           test captures
tests/             tshark comparison
```
