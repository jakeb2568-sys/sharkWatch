# sharkWatch

A packet analyzer written in C on top of libpcap. It decodes Ethernet, VLAN,
IPv4, TCP, UDP and ICMP headers by hand, prints a Wireshark-style summary per
packet, and is checked field-by-field against Wireshark's own dissectors.

This is the base for a small network intrusion detector. See the [roadmap](#roadmap).

```
$ ./sharkwatch -r samples/basic.pcap
    1   0.000000  192.168.1.10:53001 -> 192.168.1.1:53  UDP len=29
    2   0.012500  192.168.1.1:53 -> 192.168.1.10:53001  UDP len=56
    3   0.025000  192.168.1.10:51514 -> 93.184.216.34:80  TCP [SYN] seq=1000 win=64240 len=0
    4   0.037500  93.184.216.34:80 -> 192.168.1.10:51514  TCP [SYN, ACK] seq=5000 ack=1001 win=65535 len=0
    5   0.050000  192.168.1.10:51514 -> 93.184.216.34:80  TCP [ACK] seq=1001 ack=5001 win=64240 len=0
    6   0.062500  192.168.1.10:51514 -> 93.184.216.34:80  TCP [PSH, ACK] seq=1001 ack=5001 win=64240 len=37
  ...
   12   0.137500  192.168.1.10 -> 8.8.8.8  ICMP echo request id=0x0042 seq=1
   13   0.150000  8.8.8.8 -> 192.168.1.10  ICMP echo reply id=0x0042 seq=1
   14   0.162500  02:00:00:aa:aa:01 -> ff:ff:ff:ff:ff:ff  ARP

--- 15 packets, 916 bytes ---
  IPv4 13  (TCP 9, UDP 2, ICMP 2, other 0; fragments 0)
  ARP 2   IPv6 0   other L3 0
  malformed/truncated 0
```

Malformed packets are flagged rather than crashing the parser or being misread:

```
$ ./sharkwatch -v -r samples/edge_cases.pcap
   10   0.112500  192.168.1.10 -> 93.184.216.34  TCP  [!] truncated TCP header (snaplen too small?)
                   eth 02:00:00:aa:aa:01 -> 02:00:00:bb:bb:01  ttl=64 id=0x0001 hdr=20  frame=54 (captured 44)
   11   0.125000  192.168.1.10 -> 93.184.216.34  UDP  [!] bad IPv4 header length (IHL < 5)
                   eth 02:00:00:aa:aa:01 -> 02:00:00:bb:bb:01  ttl=64 id=0x0001 hdr=8  frame=42
```

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
```

Examples:

```sh
./sharkwatch -r capture.pcapng
./sharkwatch -r capture.pcapng tcp port 443          # BPF filter, same syntax as tcpdump
sudo ./sharkwatch -i eth0 -c 100 -v
sudo ./sharkwatch -i any not port 22                 # Linux "any" pseudo-interface
```

Live capture stops cleanly on Ctrl-C and prints a summary including kernel drop counts.

## How it works

```
pcap_loop ─▶ decode_packet() ─▶ packet_t ─▶ print_packet() / print_packet_tsv()
              │
              ├─ link layer:  Ethernet II (+802.1Q / Q-in-Q), Linux cooked v1/v2
              ├─ network:     IPv4 (options, fragments)
              └─ transport:   TCP (flags, options length), UDP, ICMP
```

Decoding and printing are separate. `decode.c` fills a `packet_t` struct and
never prints anything, so later stages (flow tracking, detection) can use
decoded packets without touching raw bytes.

A few design points worth calling out:

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

## Testing

### Verified against Wireshark

`make test` runs both `sharkwatch -T` and `tshark -T fields` on each sample
capture and compares 13 fields per packet (IPs, protocol, TTL, ports, TCP
flags/seq/ack/payload length, UDP length, ICMP type/code):

```
$ make test
== samples/basic.pcap: 15 packets
  163 fields compared, 0 mismatches
== samples/edge_cases.pcap: 12 packets
  frame  10: sharkwatch flagged "truncated TCP header (snaplen too small?)"  | tshark: (no warning)
  frame  11: sharkwatch flagged "bad IPv4 header length (IHL < 5)"  | tshark: Bogus IP header length (8, must be at least 20)
  frame  12: sharkwatch flagged "truncated Ethernet header"  | tshark: Malformed Packet (Exception occurred)
  101 fields compared, 0 mismatches

PASS
```

The same check passes on live captures of real traffic, for both Ethernet and
Linux-cooked link types (6,000+ fields), and on an 11,000-packet home Wi-Fi
capture recorded in Wireshark on Windows (139,762 fields, 0 mismatches). You can run it on any capture of your
own: `python3 tests/verify_against_tshark.py ./sharkwatch your.pcap`.

### Sample captures

`scripts/make_samples.py` (scapy) generates the captures in `samples/`:

- **`basic.pcap`**: a DNS lookup, a full TCP handshake, an HTTP exchange and
  teardown, a ping, and ARP.
- **`edge_cases.pcap`**: packets designed to break a careless parser:
  - Ethernet padding
  - a VLAN tag
  - IP and TCP options
  - a fragmented datagram
  - an ICMP error quoting another packet
  - IPv6
  - a snaplen-truncated frame
  - a bogus IHL
  - a 10-byte runt frame

### Fuzzing

`make sanitize` builds with AddressSanitizer and UndefinedBehaviorSanitizer.
That build was run against 20,000 randomly corrupted packets: bit flips,
truncations, bad header lengths, and wire lengths that don't match. Result: no
memory errors and no undefined behavior.

## Roadmap

- [x] **Stage 0**: open live/offline captures with libpcap
- [x] **Stage 1**: Ethernet, VLAN, Linux cooked and IPv4 decoding
- [x] **Stage 2**: TCP / UDP / ICMP decoding, tshark verification, fuzzing
- [ ] **Stage 3**: application layer: DNS names, HTTP request lines, cleartext credentials
- [ ] **Stage 4**: per-flow state tracking (hash table of connections)
- [ ] **Stage 5**: detection: port scans, SYN floods, ARP spoofing

## Layout

```
include/proto.h    on-the-wire header structs and constants
include/decode.h   packet_t, the decoded representation
src/decode.c       link / network / transport decoders
src/print.c        human-readable and TSV output
src/main.c         CLI, capture loop, stats
scripts/           sample capture generator
samples/           test captures
tests/             tshark comparison
```
