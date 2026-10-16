/*
 * decode.h - turn raw frame bytes into a structured packet_t.
 *
 * Decoding and printing are kept separate on purpose: later stages (flow
 * tracking, detection) consume packet_t directly and never touch raw bytes.
 */
#ifndef SHARKWATCH_DECODE_H
#define SHARKWATCH_DECODE_H

#include "app.h"

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>

typedef enum {
    L4_NONE = 0,    /* not IPv4, a non-first fragment, or decoding stopped early */
    L4_TCP,
    L4_UDP,
    L4_ICMP,
    L4_OTHER,       /* IPv4 carrying some other protocol (GRE, ESP, ...) */
} l4_type_t;

typedef struct packet {
    /* ---- frame ---- */
    struct timeval ts;
    uint32_t caplen;            /* bytes actually captured */
    uint32_t wirelen;           /* bytes on the wire (> caplen if snaplen cut it) */

    /* ---- layer 2 ---- */
    bool     has_mac;
    uint8_t  src_mac[6], dst_mac[6];
    bool     has_vlan;
    uint16_t vlan_id;
    uint16_t ethertype;

    /* ---- layer 3: IPv4 ---- */
    bool     has_ipv4;
    struct in_addr src_ip, dst_ip;
    uint8_t  ip_proto;
    uint8_t  ttl;
    uint8_t  ip_hdr_len;        /* bytes, 20..60 */
    uint16_t ip_total_len;
    uint16_t ip_id;
    bool     dont_fragment, more_fragments;
    uint16_t frag_offset;       /* bytes */

    /* ---- layer 4 ---- */
    l4_type_t l4;               /* which of the fields below are valid */
    uint16_t src_port, dst_port;        /* TCP, UDP */
    uint32_t tcp_seq, tcp_ack;          /* raw, not relative like Wireshark shows */
    uint8_t  tcp_flags;
    uint8_t  tcp_hdr_len;               /* bytes, 20..60 */
    uint16_t tcp_window;
    uint16_t udp_len;                   /* from the UDP header */
    uint8_t  icmp_type, icmp_code;
    uint16_t icmp_id, icmp_seq;         /* echo request/reply only */

    /* ---- payload (after the deepest header we decoded) ---- */
    const uint8_t *payload;     /* points into the captured bytes */
    uint32_t payload_len;       /* length on the wire, per the IP/UDP lengths */
    uint32_t payload_caplen;    /* how much of it was actually captured */

    /* ---- application layer (Stage 3) ---- */
    app_t    app;

    /* ---- problems ---- */
    const char *error;          /* NULL if decoded cleanly, else a static message */
    const char *notice;         /* suspicious but not malformed (set by flow tracking) */
    bool     retransmission;    /* TCP data we already saw (set by flow tracking) */
} packet_t;

/* Is this pcap link-layer type (pcap_datalink()) one we can decode? */
bool decode_linktype_supported(int linktype);

/* Decode one frame. Always fills in as much of *pkt as it safely can.
 * Returns 0 on success, -1 if the packet was truncated or malformed
 * (pkt->error then says why). Never reads past hdr->caplen bytes. */
int decode_packet(int linktype, const struct pcap_pkthdr *hdr,
                  const uint8_t *data, packet_t *pkt);

static inline bool pkt_is_fragment(const packet_t *p)
{
    return p->has_ipv4 && (p->more_fragments || p->frag_offset != 0);
}

#endif
