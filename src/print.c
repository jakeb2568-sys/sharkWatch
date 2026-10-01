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

/* "[SYN, ACK]" - same wording Wireshark uses in its Info column. */
static const char *tcp_flags_str(uint8_t f, char *buf, size_t n)
{
    static const struct { uint8_t bit; const char *name; } names[] = {
        { TCPF_FIN, "FIN" }, { TCPF_SYN, "SYN" }, { TCPF_RST, "RST" },
        { TCPF_PSH, "PSH" }, { TCPF_ACK, "ACK" }, { TCPF_URG, "URG" },
        { TCPF_ECE, "ECE" }, { TCPF_CWR, "CWR" },
    };
    size_t used = (size_t)snprintf(buf, n, "[");
    bool first = true;
    for (size_t i = 0; i < sizeof names / sizeof names[0]; i++) {
        if (!(f & names[i].bit))
            continue;
        used += (size_t)snprintf(buf + used, n - used, "%s%s",
                                 first ? "" : ", ", names[i].name);
        first = false;
    }
    if (first)
        used += (size_t)snprintf(buf + used, n - used, "<none>");
    snprintf(buf + used, n - used, "]");
    return buf;
}

static const char *icmp_name(uint8_t type, uint8_t code)
{
    switch (type) {
    case ICMP_ECHO_REPLY:    return "echo reply";
    case ICMP_ECHO_REQUEST:  return "echo request";
    case ICMP_REDIRECT:      return "redirect";
    case ICMP_TIME_EXCEEDED: return code == 0 ? "time exceeded (TTL)" : "time exceeded (reassembly)";
    case ICMP_DEST_UNREACH:
        switch (code) {
        case 0:  return "destination unreachable (network)";
        case 1:  return "destination unreachable (host)";
        case 2:  return "destination unreachable (protocol)";
        case 3:  return "destination unreachable (port)";
        case 4:  return "destination unreachable (fragmentation needed)";
        case 13: return "destination unreachable (administratively prohibited)";
        default: return "destination unreachable";
        }
    default: return NULL;
    }
}

static void print_ipv4(FILE *out, const packet_t *pkt)
{
    char s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    const char *name = ip_proto_name(pkt->ip_proto);

    ip_str(pkt->src_ip, s);
    ip_str(pkt->dst_ip, d);

    /* Endpoints: with ports if we decoded a TCP/UDP header. */
    if (pkt->l4 == L4_TCP || pkt->l4 == L4_UDP)
        fprintf(out, "%s:%u -> %s:%u  ", s, pkt->src_port, d, pkt->dst_port);
    else
        fprintf(out, "%s -> %s  ", s, d);

    if (name)
        fprintf(out, "%s", name);
    else
        fprintf(out, "IPv4 proto=%u", pkt->ip_proto);

    switch (pkt->l4) {
    case L4_TCP: {
        char flags[64];
        fprintf(out, " %s seq=%u", tcp_flags_str(pkt->tcp_flags, flags, sizeof flags),
                pkt->tcp_seq);
        if (pkt->tcp_flags & TCPF_ACK)
            fprintf(out, " ack=%u", pkt->tcp_ack);
        fprintf(out, " win=%u len=%u", pkt->tcp_window, pkt->payload_len);
        break;
    }
    case L4_UDP:
        fprintf(out, " len=%u", pkt->payload_len);
        break;
    case L4_ICMP: {
        const char *what = icmp_name(pkt->icmp_type, pkt->icmp_code);
        if (what)
            fprintf(out, " %s", what);
        else
            fprintf(out, " type=%u code=%u", pkt->icmp_type, pkt->icmp_code);
        if (pkt->icmp_type == ICMP_ECHO_REQUEST || pkt->icmp_type == ICMP_ECHO_REPLY)
            fprintf(out, " id=0x%04x seq=%u", pkt->icmp_id, pkt->icmp_seq);
        break;
    }
    case L4_OTHER:
        fprintf(out, " len=%u", pkt->payload_len);
        break;
    case L4_NONE:
        if (pkt_is_fragment(pkt))   /* later fragment: just more payload */
            fprintf(out, " len=%u", pkt->payload_len);
        break;
    }

    if (pkt_is_fragment(pkt))
        fprintf(out, "  (fragment id=0x%04x off=%u%s)", pkt->ip_id,
                pkt->frag_offset, pkt->more_fragments ? " MF" : "");
}

void print_packet_tsv(FILE *out, const packet_t *pkt, uint64_t frame_no)
{
    char s[INET_ADDRSTRLEN] = "", d[INET_ADDRSTRLEN] = "";
    if (pkt->has_ipv4) {
        ip_str(pkt->src_ip, s);
        ip_str(pkt->dst_ip, d);
    }

    fprintf(out, "%llu\t%s\t%s\t", (unsigned long long)frame_no, s, d);
    if (pkt->has_ipv4)
        fprintf(out, "%u\t%u", pkt->ip_proto, pkt->ttl);
    else
        fputc('\t', out);

    if (pkt->l4 == L4_TCP || pkt->l4 == L4_UDP)
        fprintf(out, "\t%u\t%u", pkt->src_port, pkt->dst_port);
    else
        fprintf(out, "\t\t");

    if (pkt->l4 == L4_TCP)
        fprintf(out, "\t0x%04x\t%u\t%u\t%u", pkt->tcp_flags, pkt->tcp_seq,
                pkt->tcp_ack, pkt->payload_len);
    else
        fprintf(out, "\t\t\t\t");

    if (pkt->l4 == L4_UDP)
        fprintf(out, "\t%u", pkt->udp_len);
    else
        fputc('\t', out);

    if (pkt->l4 == L4_ICMP)
        fprintf(out, "\t%u\t%u", pkt->icmp_type, pkt->icmp_code);
    else
        fprintf(out, "\t\t");

    fprintf(out, "\t%s\n", pkt->error ? pkt->error : "");
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
