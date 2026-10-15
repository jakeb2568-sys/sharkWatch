/*
 * print.h - human-readable output for decoded packets.
 */
#ifndef SHARKWATCH_PRINT_H
#define SHARKWATCH_PRINT_H

#include "decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* One summary line per packet; with verbose, a second line of L2/L3 detail.
 * rel_time is seconds since the first packet, like Wireshark's Time column. */
void print_packet(FILE *out, const packet_t *pkt, uint64_t frame_no,
                  double rel_time, bool verbose);

/* Tab-separated fields, one packet per line, for scripts and for diffing
 * against tshark. Column order (empty when not applicable):
 *   frame  ip.src  ip.dst  ip.proto  ip.ttl  srcport  dstport
 *   tcp.flags  tcp.seq_raw  tcp.ack_raw  tcp.len  udp.length
 *   icmp.type  icmp.code
 *   dns.qry.name  dns.qry.type  dns.flags.response  dns.count.answers  dns.a
 *   http.method  http.uri  http.host  http.code  http.authbasic
 *   tls.sni  tls.alpn  cmd  cmd.arg  error
 * Passwords are masked unless print_set_reveal_passwords(true).        */
void print_packet_tsv(FILE *out, const packet_t *pkt, uint64_t frame_no);

/* Show cleartext passwords instead of ******** (off by default). */
void print_set_reveal_passwords(bool on);

/* One-line description of the credential in pkt, e.g.
 * "FTP username: alice". Empty string if the packet carries none. */
const char *format_credential(const packet_t *pkt, char *buf, size_t n);

#endif
