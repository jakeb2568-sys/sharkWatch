/*
 * decode.h - turn raw frame bytes into a structured packet_t.
 *
 * Decoding and printing are kept separate on purpose: later stages (flow
 * tracking, detection) consume packet_t directly and never touch raw bytes.
 */
#ifndef WIREWATCH_DECODE_H
#define WIREWATCH_DECODE_H

#include <netinet/in.h>
#include <pcap/pcap.h>
#include <stdbool.h>
#include <stdint.h>

typedef struct {
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

    /* ---- problems ---- */
    const char *error;          /* NULL if decoded cleanly, else a static message */
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
