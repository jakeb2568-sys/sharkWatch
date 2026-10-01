/*
 * print.h - human-readable output for decoded packets.
 */
#ifndef WIREWATCH_PRINT_H
#define WIREWATCH_PRINT_H

#include "decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

/* One summary line per packet; with verbose, a second line of L2/L3 detail.
 * rel_time is seconds since the first packet, like Wireshark's Time column. */
void print_packet(FILE *out, const packet_t *pkt, uint64_t frame_no,
                  double rel_time, bool verbose);

#endif
