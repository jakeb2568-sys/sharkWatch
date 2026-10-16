/*
 * sharkWatch - a small packet analyzer built on libpcap.
 *
 * Reads packets from a live interface or a .pcap file, decodes them, and
 * prints one line per packet plus a summary at the end.
 */
#include "decode.h"
#include "flow.h"
#include "print.h"
#include "proto.h"

#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DEFAULT_SNAPLEN 65535
#define MAX_CREDS_LISTED 50

struct stats {
    unsigned long long packets, bytes, ipv4, arp, ipv6, other_l3,
                       tcp, udp, icmp, other_l4, fragments, malformed;
    unsigned long long dns_queries, dns_responses, http_requests,
                       http_responses, tls_hellos, tls_sni, creds;
};

/* Cleartext credentials are listed again in the summary: in thousands of
 * lines of output, those are the ones you most need to see. */
struct cred_seen {
    unsigned long long frame;
    char text[600];
};

struct ctx {
    int linktype;
    bool verbose;
    bool tsv;
    bool have_t0;
    struct timeval t0;
    struct stats st;
    struct cred_seen creds[MAX_CREDS_LISTED];
    int ncreds;
    flow_table_t *flows;
};

static pcap_t *g_handle;   /* for the signal handler */

static void on_sigint(int sig)
{
    (void)sig;
    if (g_handle)
        pcap_breakloop(g_handle);   /* async-signal-safe; ends pcap_loop() */
}

static double seconds_since(const struct timeval *t0, const struct timeval *t)
{
    return (double)(t->tv_sec - t0->tv_sec) + (t->tv_usec - t0->tv_usec) / 1e6;
}

static void count(struct stats *st, const packet_t *pkt, int rc)
{
    st->packets++;
    st->bytes += pkt->wirelen;
    if (rc != 0)
        st->malformed++;

    if (pkt->has_ipv4) {
        st->ipv4++;
        if (pkt_is_fragment(pkt))
            st->fragments++;
        switch (pkt->ip_proto) {
        case IPPROTO_TCP:  st->tcp++;      break;
        case IPPROTO_UDP:  st->udp++;      break;
        case IPPROTO_ICMP: st->icmp++;     break;
        default:           st->other_l4++; break;
        }
    } else if (pkt->ethertype == ETYPE_ARP) {
        st->arp++;
    } else if (pkt->ethertype == ETYPE_IPV6) {
        st->ipv6++;
    } else if (pkt->ethertype) {
        st->other_l3++;
    }

    if (pkt->retransmission)
        return;                       /* already counted when first seen */
    switch (pkt->app.type) {
    case APP_DNS:
        if (pkt->app.dns_response) st->dns_responses++; else st->dns_queries++;
        break;
    case APP_HTTP_REQUEST:  st->http_requests++;  break;
    case APP_HTTP_RESPONSE: st->http_responses++; break;
    case APP_TLS_CLIENT_HELLO:
        st->tls_hellos++;
        if (pkt->app.tls_sni[0])
            st->tls_sni++;
        break;
    default: break;
    }
    if (pkt->app.cred != CRED_NONE)
        st->creds++;
}

static void remember_credential(struct ctx *c, const packet_t *pkt)
{
    if (pkt->app.cred == CRED_NONE || pkt->retransmission || c->ncreds >= MAX_CREDS_LISTED)
        return;
    struct cred_seen *cs = &c->creds[c->ncreds++];
    char what[512], s[INET_ADDRSTRLEN], d[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &pkt->src_ip, s, sizeof s);
    inet_ntop(AF_INET, &pkt->dst_ip, d, sizeof d);
    cs->frame = c->st.packets;
    snprintf(cs->text, sizeof cs->text, "%s -> %s:%u  %s", s, d, pkt->dst_port,
             format_credential(pkt, what, sizeof what));
}

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *bytes)
{
    struct ctx *c = (struct ctx *)user;
    packet_t pkt;

    if (!c->have_t0) {
        c->t0 = hdr->ts;
        c->have_t0 = true;
    }

    int rc = decode_packet(c->linktype, hdr, bytes, &pkt);
    flow_update(c->flows, &pkt);      /* may add reassembled / per-connection info */
    count(&c->st, &pkt, rc);
    remember_credential(c, &pkt);
    if (c->tsv)
        print_packet_tsv(stdout, &pkt, c->st.packets);
    else
        print_packet(stdout, &pkt, c->st.packets, seconds_since(&c->t0, &hdr->ts), c->verbose);
}

static void print_summary(FILE *out, const struct ctx *c)
{
    const struct stats *s = &c->st;
    fprintf(out,
            "\n--- %llu packets, %llu bytes ---\n"
            "  IPv4 %llu  (TCP %llu, UDP %llu, ICMP %llu, other %llu; fragments %llu)\n"
            "  ARP %llu   IPv6 %llu   other L3 %llu\n"
            "  DNS %llu queries / %llu responses   HTTP %llu requests / %llu responses\n"
            "  TLS %llu ClientHellos (%llu with SNI)\n"
            "  malformed/truncated %llu\n",
            s->packets, s->bytes, s->ipv4, s->tcp, s->udp, s->icmp, s->other_l4,
            s->fragments, s->arp, s->ipv6, s->other_l3,
            s->dns_queries, s->dns_responses, s->http_requests, s->http_responses,
            s->tls_hellos, s->tls_sni, s->malformed);

    const flow_stats_t *f = flow_stats(c->flows);
    fprintf(out,
            "  Flows: %llu TCP (%llu handshakes, %llu mid-stream, %llu reset, %llu port reuse), "
            "%llu UDP; peak %llu active\n"
            "  Reassembly: %llu split ClientHello(s) rebuilt, %llu retransmission(s), "
            "%llu overlap conflict(s)\n",
            f->tcp_flows, f->handshakes, f->midstream, f->resets, f->port_reuse,
            f->udp_flows, f->peak_active, f->reassembled, f->retransmissions,
            f->overlap_conflicts);
    if (f->evicted || f->expired || f->reassembly_skipped)
        fprintf(out, "  Limits hit: %llu flows evicted (table full), %llu expired (idle), "
                     "%llu reassemblies skipped (memory budget)\n",
                f->evicted, f->expired, f->reassembly_skipped);

    if (s->creds) {
        fprintf(out, "\n  !! %llu cleartext credential(s) seen:\n", s->creds);
        for (int i = 0; i < c->ncreds; i++)
            fprintf(out, "     frame %-6llu %s\n", c->creds[i].frame, c->creds[i].text);
        if (s->creds > (unsigned long long)c->ncreds)
            fprintf(out, "     ... and %llu more\n", s->creds - (unsigned long long)c->ncreds);
    }
}

static void usage(FILE *out, const char *prog)
{
    fprintf(out,
            "usage: %s (-r FILE | -i IFACE) [options] [BPF filter]\n"
            "\n"
            "  -r FILE     read packets from a pcap/pcapng file\n"
            "  -i IFACE    capture live from an interface (needs root/CAP_NET_RAW)\n"
            "  -c N        stop after N packets\n"
            "  -s SNAPLEN  bytes to capture per packet (default %d)\n"
            "  -v          verbose: add an L2/L3 detail line per packet\n"
            "  -T          tab-separated fields instead (see print.h for columns)\n"
            "  -P          show cleartext passwords instead of ******** \n"
            "  -F N        after the packets, list the top N conversations by bytes\n"
            "              (0 = all; with -T, as tab-separated \"flow\" rows)\n"
            "  -m N        track at most N connections at once (default %d)\n"
            "  -h          show this help\n"
            "\n"
            "Anything after the options is a BPF filter, same syntax as\n"
            "tcpdump and Wireshark capture filters, e.g.  tcp port 443\n",
            prog, DEFAULT_SNAPLEN, FLOW_DEFAULT_MAX);
}

/* Join argv[from..] into one string, the way tcpdump does for its filter. */
static char *join_args(int argc, char **argv, int from)
{
    size_t n = 1;
    for (int i = from; i < argc; i++)
        n += strlen(argv[i]) + 1;
    char *s = calloc(1, n);
    if (!s)
        return NULL;
    for (int i = from; i < argc; i++) {
        if (i > from)
            strcat(s, " ");
        strcat(s, argv[i]);
    }
    return s;
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE] = "";
    const char *file = NULL, *iface = NULL;
    int max_packets = -1, snaplen = DEFAULT_SNAPLEN, opt;
    int report_n = 10, max_flows = 0;
    bool want_report = false;
    struct ctx c = { 0 };

    while ((opt = getopt(argc, argv, "r:i:c:s:vTPF:m:h")) != -1) {
        switch (opt) {
        case 'r': file = optarg; break;
        case 'i': iface = optarg; break;
        case 'c': max_packets = atoi(optarg); break;
        case 's': snaplen = atoi(optarg); break;
        case 'v': c.verbose = true; break;
        case 'T': c.tsv = true; break;
        case 'P': print_set_reveal_passwords(true); break;
        case 'F': report_n = atoi(optarg); want_report = report_n >= 0; break;
        case 'm': max_flows = atoi(optarg); break;
        case 'h': usage(stdout, argv[0]); return EXIT_SUCCESS;
        default:  usage(stderr, argv[0]); return EXIT_FAILURE;
        }
    }
    if (!file == !iface) {   /* exactly one of -r / -i */
        usage(stderr, argv[0]);
        return EXIT_FAILURE;
    }
    if (max_packets == 0 || snaplen <= 0 || max_flows < 0 || report_n < 0) {
        fprintf(stderr, "-c, -s and -m must be positive, -F zero or more\n");
        return EXIT_FAILURE;
    }
    if (!(c.flows = flow_table_new((unsigned)max_flows, want_report ? (unsigned)report_n : 1))) {
        fprintf(stderr, "sharkwatch: out of memory\n");
        return EXIT_FAILURE;
    }

    pcap_t *h = file ? pcap_open_offline(file, errbuf)
                     : pcap_open_live(iface, snaplen, 1, 1000, errbuf);
    if (!h) {
        fprintf(stderr, "sharkwatch: %s\n", errbuf);
        return EXIT_FAILURE;
    }

    int status = EXIT_SUCCESS;
    char *filter = join_args(argc, argv, optind);
    if (filter && *filter) {
        struct bpf_program prog;
        if (pcap_compile(h, &prog, filter, 1, PCAP_NETMASK_UNKNOWN) == -1 ||
            pcap_setfilter(h, &prog) == -1) {
            fprintf(stderr, "sharkwatch: bad filter '%s': %s\n", filter, pcap_geterr(h));
            status = EXIT_FAILURE;
            goto out;
        }
        pcap_freecode(&prog);
    }

    c.linktype = pcap_datalink(h);
    if (!decode_linktype_supported(c.linktype)) {
        fprintf(stderr, "sharkwatch: unsupported link type %s (%s)\n",
                pcap_datalink_val_to_name(c.linktype),
                pcap_datalink_val_to_description(c.linktype));
        status = EXIT_FAILURE;
        goto out;
    }

    g_handle = h;
    signal(SIGINT, on_sigint);
    signal(SIGTERM, on_sigint);

    if (pcap_loop(h, max_packets, on_packet, (u_char *)&c) == PCAP_ERROR) {
        fprintf(stderr, "sharkwatch: %s\n", pcap_geterr(h));
        status = EXIT_FAILURE;
    }

    flow_finish(c.flows);
    if (want_report)
        flow_print_report(c.flows, stdout, c.tsv);
    fflush(stdout);   /* so the summary lands after the packet lines when piped */
    print_summary(stderr, &c);
    if (iface) {
        struct pcap_stat ps;
        if (pcap_stats(h, &ps) == 0)
            fprintf(stderr, "  kernel: %u received, %u dropped\n", ps.ps_recv, ps.ps_drop);
    }

out:
    flow_table_free(c.flows);
    free(filter);
    pcap_close(h);
    return status;
}
