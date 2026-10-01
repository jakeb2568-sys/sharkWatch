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

    return 0;
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
