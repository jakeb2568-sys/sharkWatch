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
 *   icmp.type  icmp.code  error                                       */
void print_packet_tsv(FILE *out, const packet_t *pkt, uint64_t frame_no);

#endif
