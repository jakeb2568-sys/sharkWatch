/*
 * print.c - formatting decoded packets for humans.
 */
#include "print.h"
#include "proto.h"

#include <arpa/inet.h>

/* Note: we use inet_ntop() with our own buffers, not inet_ntoa(). inet_ntoa()
 * returns a pointer to one shared static buffer, so
 *     printf("%s -> %s", inet_ntoa(a), inet_ntoa(b));
 * prints the same address twice. Classic C bug. */
static const char *ip_str(struct in_addr a, char buf[INET_ADDRSTRLEN])
{
    return inet_ntop(AF_INET, &a, buf, INET_ADDRSTRLEN);
}

static const char *mac_str(const uint8_t m[6], char buf[18])
{
    snprintf(buf, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             m[0], m[1], m[2], m[3], m[4], m[5]);
    return buf;
}

static const char *ethertype_name(uint16_t t)
{
    switch (t) {
    case ETYPE_IPV4: return "IPv4";
    case ETYPE_ARP:  return "ARP";
    case ETYPE_IPV6: return "IPv6";
    default:         return NULL;
    }
}

static const char *ip_proto_name(uint8_t p)
{
    switch (p) {
    case IPPROTO_ICMP: return "ICMP";
    case IPPROTO_TCP:  return "TCP";
    case IPPROTO_UDP:  return "UDP";
    default:           return NULL;
    }
}

static void print_ipv4(FILE *out, const packet_t *pkt)
{
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    const char *name = ip_proto_name(pkt->ip_proto);

    fprintf(out, "%s -> %s  ", ip_str(pkt->src_ip, s), ip_str(pkt->dst_ip, d));
    if (name)
        fprintf(out, "%s", name);
    else
        fprintf(out, "IPv4 proto=%u", pkt->ip_proto);
    if (pkt_is_fragment(pkt))
        fprintf(out, " (fragment id=0x%04x off=%u%s)", pkt->ip_id,
                pkt->frag_offset, pkt->more_fragments ? " MF" : "");
    fprintf(out, " len=%u", pkt->ip_total_len);
}

static void print_l2_only(FILE *out, const packet_t *pkt)
{
    char s[18], d[18];
    const char *name = ethertype_name(pkt->ethertype);

    if (pkt->has_mac)
        fprintf(out, "%s -> %s  ", mac_str(pkt->src_mac, s), mac_str(pkt->dst_mac, d));
    if (name)
        fprintf(out, "%s", name);
    else
        fprintf(out, "ethertype 0x%04x", pkt->ethertype);
    if (pkt->ethertype == ETYPE_IPV6)
        fprintf(out, " (not decoded yet)");
}

void print_packet(FILE *out, const packet_t *pkt, uint64_t frame_no,
                  double rel_time, bool verbose)
{
    fprintf(out, "%5llu %10.6f  ", (unsigned long long)frame_no, rel_time);

    if (pkt->has_ipv4)
        print_ipv4(out, pkt);
    else if (pkt->ethertype || pkt->has_mac)
        print_l2_only(out, pkt);

    if (pkt->error)
        fprintf(out, "  [!] %s", pkt->error);
    fputc('\n', out);

    if (!verbose)
        return;

    fprintf(out, "                   ");
    if (pkt->has_mac) {
        char s[18], d[18];
        fprintf(out, "eth %s -> %s  ", mac_str(pkt->src_mac, s), mac_str(pkt->dst_mac, d));
    }
    if (pkt->has_vlan)
        fprintf(out, "vlan=%u  ", pkt->vlan_id);
    if (pkt->has_ipv4)
        fprintf(out, "ttl=%u id=0x%04x hdr=%u%s  ", pkt->ttl, pkt->ip_id,
                pkt->ip_hdr_len, pkt->dont_fragment ? " DF" : "");
    fprintf(out, "frame=%u", pkt->wirelen);
    if (pkt->caplen < pkt->wirelen)
        fprintf(out, " (captured %u)", pkt->caplen);
    fputc('\n', out);
}
