/*
 * decode.c - protocol decoding.
 *
 * Every decoder follows the same rule: check that the bytes exist before
 * reading them. Captures are untrusted input - a truncated or hostile packet
 * must produce an error message, never an out-of-bounds read.
 */
#include "decode.h"
#include "proto.h"

#include <arpa/inet.h>
#include <string.h>

/* Older libpcap (< 1.10, e.g. some macOS versions) predates cooked v2. */
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif

static int fail(packet_t *pkt, const char *why)
{
    pkt->error = why;
    return -1;
}

bool decode_linktype_supported(int linktype)
{
    return linktype == DLT_EN10MB ||
           linktype == DLT_LINUX_SLL ||
           linktype == DLT_LINUX_SLL2;
}

/* ------------------------------------------------------------------------ */
/* Layer 4                                                                  */
/*                                                                          */
/* Each decoder gets two lengths:                                           */
/*   cap  - bytes we actually have in memory starting at p                  */
/*   wire - bytes the IP header says the segment is                         */
/* They differ when snaplen truncated the capture (cap < wire).             */
/* ------------------------------------------------------------------------ */

static void set_payload(packet_t *pkt, const uint8_t *p, uint32_t cap,
                        uint32_t wire, uint32_t hdr_len)
{
    pkt->payload        = p + hdr_len;
    pkt->payload_len    = wire > hdr_len ? wire - hdr_len : 0;
    pkt->payload_caplen = cap  > hdr_len ? cap  - hdr_len : 0;
}

static int decode_tcp(const uint8_t *p, uint32_t cap, uint32_t wire, packet_t *pkt)
{
    if (wire < TCP_MIN_HDR_LEN)
        return fail(pkt, "IP datagram too short for a TCP header");
    if (cap < TCP_MIN_HDR_LEN)
        return fail(pkt, "truncated TCP header (snaplen too small?)");

    struct tcp_hdr t;
    memcpy(&t, p, sizeof t);

    pkt->l4          = L4_TCP;
    pkt->src_port    = ntohs(t.sport);
    pkt->dst_port    = ntohs(t.dport);
    pkt->tcp_seq     = ntohl(t.seq);
    pkt->tcp_ack     = ntohl(t.ack);
    pkt->tcp_flags   = t.flags;
    pkt->tcp_window  = ntohs(t.window);
    pkt->tcp_hdr_len = (t.data_off >> 4) * 4;

    if (pkt->tcp_hdr_len < TCP_MIN_HDR_LEN)
        return fail(pkt, "bad TCP header length (data offset < 5)");
    if (pkt->tcp_hdr_len > wire)
        return fail(pkt, "TCP header longer than the IP datagram");
    if (pkt->tcp_hdr_len > cap)
        return fail(pkt, "truncated TCP options");

    set_payload(pkt, p, cap, wire, pkt->tcp_hdr_len);
    return 0;
}

static int decode_udp(const uint8_t *p, uint32_t cap, uint32_t wire, packet_t *pkt)
{
    if (wire < UDP_HDR_LEN)
        return fail(pkt, "IP datagram too short for a UDP header");
    if (cap < UDP_HDR_LEN)
        return fail(pkt, "truncated UDP header (snaplen too small?)");

    struct udp_hdr u;
    memcpy(&u, p, sizeof u);

    pkt->l4       = L4_UDP;
    pkt->src_port = ntohs(u.sport);
    pkt->dst_port = ntohs(u.dport);
    pkt->udp_len  = ntohs(u.length);

    set_payload(pkt, p, cap, wire, UDP_HDR_LEN);

    /* In the first fragment of a fragmented datagram, the UDP length covers
     * the whole reassembled datagram, so it's legitimately bigger than this
     * piece. Only sanity-check it for unfragmented packets. */
    if (!pkt->more_fragments) {
        if (pkt->udp_len < UDP_HDR_LEN || pkt->udp_len > wire)
            return fail(pkt, "UDP length field disagrees with IP length");
        set_payload(pkt, p, cap, pkt->udp_len, UDP_HDR_LEN);
    }
    return 0;
}

static int decode_icmp(const uint8_t *p, uint32_t cap, uint32_t wire, packet_t *pkt)
{
    if (wire < ICMP_HDR_LEN)
        return fail(pkt, "IP datagram too short for an ICMP header");
    if (cap < ICMP_HDR_LEN)
        return fail(pkt, "truncated ICMP header (snaplen too small?)");

    struct icmp_hdr ic;
    memcpy(&ic, p, sizeof ic);

    pkt->l4        = L4_ICMP;
    pkt->icmp_type = ic.type;
    pkt->icmp_code = ic.code;
    if (ic.type == ICMP_ECHO_REQUEST || ic.type == ICMP_ECHO_REPLY) {
        pkt->icmp_id  = ntohs(ic.id);
        pkt->icmp_seq = ntohs(ic.seq);
    }
    /* For errors (unreachable, time exceeded) the payload is the IP header
     * + first 8 bytes of the packet that triggered it. Decoding that is a
     * later stage; for now it's just payload. */
    set_payload(pkt, p, cap, wire, ICMP_HDR_LEN);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Layer 3                                                                  */
/* ------------------------------------------------------------------------ */

static int decode_ipv4(const uint8_t *p, uint32_t len, packet_t *pkt)
{
    if (len < IPV4_MIN_HDR_LEN)
        return fail(pkt, "truncated IPv4 header");

    struct ipv4_hdr ip;
    memcpy(&ip, p, sizeof ip);

    uint8_t version = ip.ver_ihl >> 4;
    uint8_t hdr_len = (ip.ver_ihl & 0x0F) * 4;   /* IHL counts 32-bit words */
    uint16_t frag   = ntohs(ip.frag);

    if (version != 4)
        return fail(pkt, "IPv4 ethertype but IP version is not 4");

    /* The fixed 20 bytes are present, so record them even if the rest of
     * the header turns out to be bad: a partial answer beats none. */
    pkt->has_ipv4       = true;
    pkt->src_ip.s_addr  = ip.src;   /* in_addr wants network order: no ntohl */
    pkt->dst_ip.s_addr  = ip.dst;
    pkt->ip_proto       = ip.protocol;
    pkt->ttl            = ip.ttl;
    pkt->ip_hdr_len     = hdr_len;
    pkt->ip_total_len   = ntohs(ip.total_len);
    pkt->ip_id          = ntohs(ip.id);
    pkt->dont_fragment  = frag & IPV4_FLAG_DF;
    pkt->more_fragments = frag & IPV4_FLAG_MF;
    pkt->frag_offset    = (frag & IPV4_FRAG_MASK) * 8;

    if (hdr_len < IPV4_MIN_HDR_LEN)
        return fail(pkt, "bad IPv4 header length (IHL < 5)");
    if (hdr_len > len)
        return fail(pkt, "truncated IPv4 options");
    if (pkt->ip_total_len < hdr_len)
        return fail(pkt, "IPv4 total length smaller than header");
    /* If nothing was cut off by snaplen, the datagram must fit in the frame. */
    if (pkt->caplen == pkt->wirelen && pkt->ip_total_len > len)
        return fail(pkt, "IPv4 total length larger than the frame");

    /* Where does the datagram end? Trust the IP total length, not the frame:
     *  - Ethernet pads frames to 60 bytes, so a tiny packet arrives with
     *    trailing zeros that are NOT payload.
     *  - snaplen can cut the frame short, so we may hold less than that.  */
    uint32_t wire = pkt->ip_total_len - hdr_len;
    uint32_t cap  = len - hdr_len;
    if (cap > wire)
        cap = wire;
    p += hdr_len;

    /* Only the first fragment (offset 0) carries the TCP/UDP header. Later
     * fragments are just a continuation of the payload. */
    if (pkt->frag_offset != 0) {
        set_payload(pkt, p, cap, wire, 0);
        return 0;
    }

    switch (pkt->ip_proto) {
    case IPPROTO_TCP:  return decode_tcp(p, cap, wire, pkt);
    case IPPROTO_UDP:  return decode_udp(p, cap, wire, pkt);
    case IPPROTO_ICMP: return decode_icmp(p, cap, wire, pkt);
    default:
        pkt->l4 = L4_OTHER;
        set_payload(pkt, p, cap, wire, 0);
        return 0;
    }
}

/* ------------------------------------------------------------------------ */
/* Layer 2 / entry point                                                    */
/* ------------------------------------------------------------------------ */

int decode_packet(int linktype, const struct pcap_pkthdr *hdr,
                  const uint8_t *data, packet_t *pkt)
{
    memset(pkt, 0, sizeof *pkt);
    pkt->ts      = hdr->ts;
    pkt->caplen  = hdr->caplen;
    pkt->wirelen = hdr->len;

    const uint8_t *p = data;
    uint32_t len = hdr->caplen;     /* bytes remaining from p onward */
    uint16_t ethertype;

    switch (linktype) {
    case DLT_EN10MB: {
        if (len < ETH_HDR_LEN)
            return fail(pkt, "truncated Ethernet header");
        struct eth_hdr eth;
        memcpy(&eth, p, sizeof eth);
        memcpy(pkt->dst_mac, eth.dst, ETH_ADDR_LEN);
        memcpy(pkt->src_mac, eth.src, ETH_ADDR_LEN);
        pkt->has_mac = true;
        ethertype = ntohs(eth.ethertype);
        p += ETH_HDR_LEN;
        len -= ETH_HDR_LEN;

        /* Peel off any VLAN tags (two of them for Q-in-Q). We remember the
         * outermost VLAN ID. */
        while (ethertype == ETYPE_VLAN || ethertype == ETYPE_QINQ) {
            if (len < VLAN_TAG_LEN)
                return fail(pkt, "truncated VLAN tag");
            struct vlan_tag tag;
            memcpy(&tag, p, sizeof tag);
            if (!pkt->has_vlan) {
                pkt->has_vlan = true;
                pkt->vlan_id  = ntohs(tag.tci) & 0x0FFF;
            }
            ethertype = ntohs(tag.ethertype);
            p += VLAN_TAG_LEN;
            len -= VLAN_TAG_LEN;
        }
        break;
    }
    case DLT_LINUX_SLL:
        if (len < SLL_HDR_LEN)
            return fail(pkt, "truncated Linux cooked header");
        ethertype = (uint16_t)(p[14] << 8 | p[15]);
        p += SLL_HDR_LEN;
        len -= SLL_HDR_LEN;
        break;
    case DLT_LINUX_SLL2:
        if (len < SLL2_HDR_LEN)
            return fail(pkt, "truncated Linux cooked v2 header");
        ethertype = (uint16_t)(p[0] << 8 | p[1]);
        p += SLL2_HDR_LEN;
        len -= SLL2_HDR_LEN;
        break;
    default:
        return fail(pkt, "unsupported link type");
    }

    pkt->ethertype = ethertype;
    if (ethertype == ETYPE_IPV4)
        return decode_ipv4(p, len, pkt);
    return 0;   /* ARP, IPv6, etc.: layer 2 only for now */
}
