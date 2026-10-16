/*
 * flow.h - connection tracking (Stage 4).
 *
 * Groups packets into flows (one TCP connection or UDP conversation), tracks
 * TCP state, reassembles the start of TCP streams so messages split across
 * segments can be decoded, and keeps per-connection context (FTP USER/PASS
 * pairing, HTTP request/response matching).
 *
 * An IDS's own state is an attack surface: an attacker who can make it store
 * unbounded data per packet can exhaust its memory and blind it. So every
 * resource here is capped:
 *   - the number of flows (least-recently-used flow evicted when full),
 *   - idle flows expire,
 *   - the reassembly buffer per stream (first 16 KB, and only when needed),
 *   - total reassembly memory across all flows,
 * and the hash table uses a secret random key (SipHash) so an attacker can't
 * pick addresses/ports that all land in one bucket ("hash flooding").
 */
#ifndef SHARKWATCH_FLOW_H
#define SHARKWATCH_FLOW_H

#include "decode.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#define FLOW_DEFAULT_MAX     65536
#define FLOW_IDLE_TIMEOUT    300        /* seconds without a packet */
#define STREAM_HEAD_MAX      16384      /* bytes reassembled per direction */
#define STREAM_MAX_SEGMENTS  64         /* give up on a head after this many */
#define REASSEMBLY_BUDGET    (64u * 1024 * 1024)   /* all buffers together */

typedef enum {
    TCP_NONE = 0,          /* UDP flows */
    TCP_SYN_SENT,          /* client SYN seen */
    TCP_SYN_RECEIVED,      /* server SYN-ACK seen */
    TCP_ESTABLISHED,
    TCP_CLOSING,           /* one side sent FIN */
    TCP_CLOSED,            /* both FINs, or RST */
    TCP_MIDSTREAM,         /* capture started after the handshake */
} tcp_state_t;

/* Per-direction stream state. Direction 0 = client -> server. */
typedef struct {
    bool     have_base;
    uint32_t base_seq;     /* sequence number of the stream's first byte */
    uint8_t *buf;          /* STREAM_HEAD_MAX bytes, allocated only when needed */
    uint8_t *have;         /* bitmap: which bytes of buf are filled */
    uint32_t contig;       /* bytes filled contiguously from offset 0 */
    uint32_t segments;     /* segments copied into buf */
    bool     done;         /* first message decoded (or given up on) */
    bool     have_max;
    uint32_t max_end;      /* highest sequence number seen (end of data) */
} stream_t;

typedef struct flow {
    /* identity: client = side that sent the SYN (or best guess) */
    uint8_t  proto;
    struct in_addr cli_ip, srv_ip;
    uint16_t cli_port, srv_port;

    struct timeval first, last;
    uint64_t pkts[2], bytes[2];        /* [0] client->server, [1] server->client */
    tcp_state_t state;
    bool     fin[2], rst;
    unsigned overlap_conflicts;        /* retransmitted bytes that changed */

    stream_t stream[2];

    /* per-connection application context */
    char     label[96];                /* SNI / Host / DNS name for the report */
    char     ftp_user[64];             /* last USER seen, waiting for PASS */
    char     last_request[160];        /* last HTTP request, for its response */

    /* bookkeeping */
    struct flow *hnext;                /* hash bucket chain */
    struct flow *lru_prev, *lru_next;  /* least-recently-used order */
    uint64_t id;                       /* order of creation */
} flow_t;

/* Finished-flow summary kept for the conversations report. */
typedef struct {
    uint8_t  proto;
    struct in_addr cli_ip, srv_ip;
    uint16_t cli_port, srv_port;
    struct timeval first, last;
    uint64_t pkts[2], bytes[2];
    tcp_state_t state;
    char     label[96];
    uint64_t id;
} flow_summary_t;

typedef struct {
    unsigned long long tcp_flows, udp_flows, handshakes, resets, midstream,
                       port_reuse, expired, evicted, peak_active,
                       reassembled, reassembly_skipped, overlap_conflicts,
                       retransmissions;
} flow_stats_t;

typedef struct flow_table flow_table_t;

/* max_flows: cap on simultaneously tracked flows (0 = default).
 * report_n: how many conversations to keep for the report (0 = all). */
flow_table_t *flow_table_new(unsigned max_flows, unsigned report_n);
void flow_table_free(flow_table_t *t);

/* Account the packet to its flow. May enrich pkt->app (reassembled TLS
 * hello, paired FTP login, HTTP request a response answers) and set
 * pkt->notice. Packets without TCP/UDP ports are ignored. */
void flow_update(flow_table_t *t, packet_t *pkt);

/* End of capture: finish every live flow, then print the top conversations
 * by bytes (human table, or "flow"-prefixed TSV rows for scripts). */
void flow_finish(flow_table_t *t);
void flow_print_report(const flow_table_t *t, FILE *out, bool tsv);
const flow_stats_t *flow_stats(const flow_table_t *t);
unsigned long long flow_active(const flow_table_t *t);

const char *tcp_state_name(tcp_state_t s);

#endif
