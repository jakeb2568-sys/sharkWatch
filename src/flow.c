/*
 * flow.c - connection tracking, TCP state, stream-head reassembly.
 * See flow.h for the design and its resource limits.
 */
#include "flow.h"
#include "app.h"
#include "proto.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct flow_table {
    flow_t  **buckets;
    size_t    nbuckets;                 /* power of two */
    flow_t   *lru_head, *lru_tail;      /* head = least recently used */
    flow_t   *free_list;                /* recycled flow_t structs */
    unsigned long long active;
    unsigned  max_flows;
    uint64_t  next_id;
    uint8_t   key[16];                  /* SipHash key, random per run */
    size_t    reasm_bytes;              /* reassembly memory in use */

    flow_summary_t *report;             /* finished flows kept for the report */
    size_t    nreport, report_cap;
    unsigned  report_n;                 /* keep top N by bytes; 0 = keep all */

    flow_stats_t st;
};

/* ------------------------------------------------------------------------ */
/* SipHash-2-4 (Aumasson & Bernstein)                                       */
/*                                                                          */
/* A hash table with a predictable hash function can be attacked: send     */
/* packets whose addresses/ports all hash to one bucket and every lookup    */
/* becomes a linear scan ("hash flooding", the same attack that hit many    */
/* web frameworks in 2011). SipHash is a fast keyed hash; with a random     */
/* secret key, an attacker can't predict which bucket anything lands in.    */
/* ------------------------------------------------------------------------ */

#define ROTL(x, b) (uint64_t)(((x) << (b)) | ((x) >> (64 - (b))))
#define SIPROUND                                                         \
    do {                                                                 \
        v0 += v1; v1 = ROTL(v1, 13); v1 ^= v0; v0 = ROTL(v0, 32);        \
        v2 += v3; v3 = ROTL(v3, 16); v3 ^= v2;                           \
        v0 += v3; v3 = ROTL(v3, 21); v3 ^= v0;                           \
        v2 += v1; v1 = ROTL(v1, 17); v1 ^= v2; v2 = ROTL(v2, 32);        \
    } while (0)

static uint64_t rd64le(const uint8_t *p)
{
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--)
        v = v << 8 | p[i];
    return v;
}

uint64_t siphash24(const uint8_t key[16], const uint8_t *in, size_t len);
uint64_t siphash24(const uint8_t key[16], const uint8_t *in, size_t len)
{
    uint64_t k0 = rd64le(key), k1 = rd64le(key + 8);
    uint64_t v0 = 0x736f6d6570736575ULL ^ k0, v1 = 0x646f72616e646f6dULL ^ k1;
    uint64_t v2 = 0x6c7967656e657261ULL ^ k0, v3 = 0x7465646279746573ULL ^ k1;
    size_t i = 0;

    for (; i + 8 <= len; i += 8) {
        uint64_t m = rd64le(in + i);
        v3 ^= m; SIPROUND; SIPROUND; v0 ^= m;
    }
    uint64_t b = (uint64_t)len << 56;
    for (size_t j = 0; i + j < len; j++)
        b |= (uint64_t)in[i + j] << (8 * j);
    v3 ^= b; SIPROUND; SIPROUND; v0 ^= b;
    v2 ^= 0xff; SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static void random_key(uint8_t key[16])
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd >= 0) {
        ssize_t got = read(fd, key, 16);
        close(fd);
        if (got == 16)
            return;
    }
    /* Fallback: not secret, but still varies per run. */
    uint64_t a = (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    for (int i = 0; i < 16; i++)
        key[i] = (uint8_t)(a >> ((i % 8) * 8)) ^ (uint8_t)(i * 97);
}

/* ------------------------------------------------------------------------ */
/* Keys and lookup                                                          */
/* ------------------------------------------------------------------------ */

/* Both directions of a connection must find the same flow, so the key puts
 * the two endpoints in a fixed order (smaller address:port first). It's
 * serialised byte by byte so struct padding can't leak into the hash. */
static uint64_t flow_hash(const flow_table_t *t, uint8_t proto,
                          struct in_addr a, uint16_t pa, struct in_addr b, uint16_t pb)
{
    uint64_t ea = (uint64_t)ntohl(a.s_addr) << 16 | pa;
    uint64_t eb = (uint64_t)ntohl(b.s_addr) << 16 | pb;
    if (ea > eb) {
        uint64_t tmp = ea; ea = eb; eb = tmp;
    }
    uint8_t buf[13];
    for (int i = 0; i < 6; i++) {
        buf[i]     = (uint8_t)(ea >> (8 * i));
        buf[6 + i] = (uint8_t)(eb >> (8 * i));
    }
    buf[12] = proto;
    return siphash24(t->key, buf, sizeof buf);
}

static size_t bucket_of(const flow_table_t *t, const flow_t *f)
{
    return flow_hash(t, f->proto, f->cli_ip, f->cli_port, f->srv_ip, f->srv_port) &
           (t->nbuckets - 1);
}

/* Returns the flow and sets *dir: 0 if the packet goes client -> server. */
static flow_t *flow_lookup(flow_table_t *t, const packet_t *pkt, size_t bucket, int *dir)
{
    for (flow_t *f = t->buckets[bucket]; f; f = f->hnext) {
        if (f->proto != pkt->ip_proto)
            continue;
        if (f->cli_ip.s_addr == pkt->src_ip.s_addr && f->cli_port == pkt->src_port &&
            f->srv_ip.s_addr == pkt->dst_ip.s_addr && f->srv_port == pkt->dst_port) {
            *dir = 0;
            return f;
        }
        if (f->cli_ip.s_addr == pkt->dst_ip.s_addr && f->cli_port == pkt->dst_port &&
            f->srv_ip.s_addr == pkt->src_ip.s_addr && f->srv_port == pkt->src_port) {
            *dir = 1;
            return f;
        }
    }
    return NULL;
}

/* ------------------------------------------------------------------------ */
/* LRU list: every packet moves its flow to the tail, so the head is always */
/* the flow that has been quiet the longest. Eviction and expiry are O(1).  */
/* ------------------------------------------------------------------------ */

static void lru_unlink(flow_table_t *t, flow_t *f)
{
    if (f->lru_prev) f->lru_prev->lru_next = f->lru_next; else t->lru_head = f->lru_next;
    if (f->lru_next) f->lru_next->lru_prev = f->lru_prev; else t->lru_tail = f->lru_prev;
    f->lru_prev = f->lru_next = NULL;
}

static void lru_append(flow_table_t *t, flow_t *f)
{
    f->lru_prev = t->lru_tail;
    f->lru_next = NULL;
    if (t->lru_tail) t->lru_tail->lru_next = f; else t->lru_head = f;
    t->lru_tail = f;
}

/* ------------------------------------------------------------------------ */
/* Report store                                                             */
/* ------------------------------------------------------------------------ */

static uint64_t total_bytes(const flow_summary_t *s) { return s->bytes[0] + s->bytes[1]; }

/* Bigger first; ties broken by creation order so output is deterministic. */
static int summary_cmp(const void *a, const void *b)
{
    const flow_summary_t *x = a, *y = b;
    uint64_t bx = total_bytes(x), by = total_bytes(y);
    if (bx != by)
        return bx > by ? -1 : 1;
    return x->id < y->id ? -1 : x->id > y->id;
}

static void report_add(flow_table_t *t, const flow_t *f)
{
    flow_summary_t s;
    memset(&s, 0, sizeof s);
    s.proto = f->proto;
    s.cli_ip = f->cli_ip; s.srv_ip = f->srv_ip;
    s.cli_port = f->cli_port; s.srv_port = f->srv_port;
    s.first = f->first; s.last = f->last;
    memcpy(s.pkts, f->pkts, sizeof s.pkts);
    memcpy(s.bytes, f->bytes, sizeof s.bytes);
    s.state = f->state;
    memcpy(s.label, f->label, sizeof s.label);
    s.id = f->id;

    if (t->report_n == 0 || t->nreport < t->report_n) {
        if (t->nreport == t->report_cap) {
            size_t cap = t->report_cap ? t->report_cap * 2 : 64;
            flow_summary_t *r = realloc(t->report, cap * sizeof *r);
            if (!r)
                return;                          /* out of memory: drop from report */
            t->report = r;
            t->report_cap = cap;
        }
        t->report[t->nreport++] = s;
        return;
    }
    /* Keeping only the top N: replace the smallest if this one is bigger. */
    size_t min = 0;
    for (size_t i = 1; i < t->nreport; i++)
        if (summary_cmp(&t->report[i], &t->report[min]) > 0)
            min = i;
    if (summary_cmp(&s, &t->report[min]) < 0)
        t->report[min] = s;
}

/* ------------------------------------------------------------------------ */
/* Flow lifecycle                                                           */
/* ------------------------------------------------------------------------ */

#define STREAM_ALLOC (STREAM_HEAD_MAX + STREAM_HEAD_MAX / 8)

static void stream_release(flow_table_t *t, stream_t *s)
{
    if (s->buf) {
        free(s->buf);                            /* bitmap lives in the same block */
        t->reasm_bytes -= STREAM_ALLOC;
    }
    s->buf = s->have = NULL;
}

static void flow_remove(flow_table_t *t, flow_t *f)
{
    report_add(t, f);
    stream_release(t, &f->stream[0]);
    stream_release(t, &f->stream[1]);

    flow_t **pp = &t->buckets[bucket_of(t, f)];
    while (*pp && *pp != f)
        pp = &(*pp)->hnext;
    if (*pp)
        *pp = f->hnext;
    lru_unlink(t, f);

    f->hnext = t->free_list;
    t->free_list = f;
    t->active--;
}

static bool is_service_port(uint16_t p)
{
    return p < 1024 || p == 1900 || p == 3478 || p == 5353 || p == 5355 ||
           p == 8080 || p == 8443;
}

static flow_t *flow_create(flow_table_t *t, const packet_t *pkt, size_t bucket)
{
    if (t->active >= t->max_flows && t->lru_head) {
        t->st.evicted++;                         /* table full: drop the quietest */
        flow_remove(t, t->lru_head);
    }
    flow_t *f = t->free_list;
    if (f)
        t->free_list = f->hnext;
    else if (!(f = malloc(sizeof *f)))
        return NULL;
    memset(f, 0, sizeof *f);

    /* Who's the client? Whoever sent the SYN. Without one (capture started
     * mid-connection, or UDP), assume the side on a well-known port is the
     * server, then the lower port, then whoever spoke first. */
    bool tcp = pkt->ip_proto == IPPROTO_TCP;
    uint8_t fl = pkt->tcp_flags;
    bool src_is_client;
    if (tcp && (fl & TCPF_SYN))
        src_is_client = !(fl & TCPF_ACK);
    else if (is_service_port(pkt->dst_port) != is_service_port(pkt->src_port))
        src_is_client = is_service_port(pkt->dst_port);
    else
        src_is_client = pkt->dst_port <= pkt->src_port;

    f->proto = pkt->ip_proto;
    f->cli_ip   = src_is_client ? pkt->src_ip : pkt->dst_ip;
    f->srv_ip   = src_is_client ? pkt->dst_ip : pkt->src_ip;
    f->cli_port = src_is_client ? pkt->src_port : pkt->dst_port;
    f->srv_port = src_is_client ? pkt->dst_port : pkt->src_port;
    f->first = pkt->ts;
    f->id = t->next_id++;

    if (!tcp) {
        f->state = TCP_NONE;
        t->st.udp_flows++;
    } else {
        t->st.tcp_flows++;
        if ((fl & TCPF_SYN) && !(fl & TCPF_ACK)) {
            f->state = TCP_SYN_SENT;
        } else if ((fl & TCPF_SYN) && (fl & TCPF_ACK)) {
            f->state = TCP_SYN_RECEIVED;
        } else {
            f->state = TCP_MIDSTREAM;
            t->st.midstream++;
        }
    }

    f->hnext = t->buckets[bucket];
    t->buckets[bucket] = f;
    lru_append(t, f);
    if (++t->active > t->st.peak_active)
        t->st.peak_active = t->active;
    return f;
}

static void expire_idle(flow_table_t *t, const struct timeval *now)
{
    while (t->lru_head && now->tv_sec - t->lru_head->last.tv_sec > FLOW_IDLE_TIMEOUT) {
        t->st.expired++;
        flow_remove(t, t->lru_head);
    }
}

/* ------------------------------------------------------------------------ */
/* TCP state                                                                */
/* ------------------------------------------------------------------------ */

static void tcp_track(flow_table_t *t, flow_t *f, int dir, uint8_t fl)
{
    if (fl & TCPF_RST) {
        if (!f->rst)
            t->st.resets++;
        f->rst = true;
        f->state = TCP_CLOSED;
        return;
    }
    if ((fl & TCPF_SYN) && (fl & TCPF_ACK) && dir == 1 && f->state == TCP_SYN_SENT)
        f->state = TCP_SYN_RECEIVED;
    else if ((fl & TCPF_ACK) && !(fl & TCPF_SYN) && dir == 0 && f->state == TCP_SYN_RECEIVED) {
        f->state = TCP_ESTABLISHED;
        t->st.handshakes++;
    }
    if (fl & TCPF_FIN) {
        f->fin[dir] = true;
        if (f->state != TCP_CLOSED)
            f->state = (f->fin[0] && f->fin[1]) ? TCP_CLOSED : TCP_CLOSING;
    }
}

/* ------------------------------------------------------------------------ */
/* Stream-head reassembly                                                   */
/*                                                                          */
/* Only the start of each direction is rebuilt (the first message: a TLS    */
/* ClientHello), and only if the first segment didn't hold all of it.       */
/* Segments are placed by sequence number, so out-of-order arrival and      */
/* retransmissions work. If a retransmission carries *different* bytes for */
/* the same sequence numbers, that's suspicious: overlapping segments with  */
/* conflicting data are a classic way to make an IDS see one thing while    */
/* the receiving host sees another (Ptacek & Newsham, 1998). We keep the    */
/* first copy and flag the packet.                                          */
/* ------------------------------------------------------------------------ */

static bool bit_get(const uint8_t *bm, uint32_t i) { return bm[i >> 3] & (1u << (i & 7)); }
static void bit_set(uint8_t *bm, uint32_t i)       { bm[i >> 3] |= (uint8_t)(1u << (i & 7)); }

/* Sequence numbers wrap at 2^32, so "a is before b" is decided by the sign
 * of the 32-bit difference (RFC 1982 serial-number arithmetic). */
static bool seq_le(uint32_t a, uint32_t b) { return (int32_t)(a - b) <= 0; }

/* Copy a segment into the stream-head buffer. Returns 1 if it added bytes
 * we didn't have, 0 if it added none, -1 if the head isn't being buffered. */
static int head_add(flow_table_t *t, flow_t *f, stream_t *s, packet_t *pkt, uint32_t seq)
{
    if (s->done || pkt->payload_caplen == 0)
        return -1;

    /* Unsigned subtraction handles sequence-number wraparound: a segment
     * from before the base comes out huge and is ignored. */
    uint32_t off = seq - s->base_seq;
    if (off >= STREAM_HEAD_MAX)
        return -1;

    if (!s->buf) {
        bool needs_more = (pkt->app.type == APP_TLS_CLIENT_HELLO && pkt->app.tls_partial) ||
                          (pkt->app.type == APP_NONE &&
                           app_tls_needs_more(pkt->payload, pkt->payload_caplen));
        if (off == 0 && !needs_more) {           /* first segment was complete: nothing to do */
            s->done = true;
            return -1;
        }
        if (t->reasm_bytes + STREAM_ALLOC > REASSEMBLY_BUDGET ||
            !(s->buf = calloc(1, STREAM_ALLOC))) {
            t->st.reassembly_skipped++;          /* over budget: degrade, don't grow */
            s->done = true;
            return -1;
        }
        s->have = s->buf + STREAM_HEAD_MAX;
        t->reasm_bytes += STREAM_ALLOC;
    }

    uint32_t n = pkt->payload_caplen;
    if (n > STREAM_HEAD_MAX - off)
        n = STREAM_HEAD_MAX - off;
    bool conflict = false, added = false;
    for (uint32_t i = 0; i < n; i++) {
        uint32_t pos = off + i;
        if (bit_get(s->have, pos)) {
            if (s->buf[pos] != pkt->payload[i])
                conflict = true;                 /* keep the first copy */
        } else {
            s->buf[pos] = pkt->payload[i];
            bit_set(s->have, pos);
            added = true;
        }
    }
    if (conflict) {
        f->overlap_conflicts++;
        t->st.overlap_conflicts++;
        pkt->notice = "overlapping TCP segment with different data (first copy kept)";
    }
    if (!added)
        return 0;                                /* pure retransmission: nothing new */
    s->segments++;

    uint32_t before = s->contig;
    while (s->contig < STREAM_HEAD_MAX && bit_get(s->have, s->contig))
        s->contig++;

    if (s->contig > before && s->segments >= 2 &&
        decode_app_reassembled(pkt, s->buf, s->contig, s->segments)) {
        if (pkt->app.reassembled_segments)
            t->st.reassembled++;
        s->done = true;
    }
    if (s->contig >= STREAM_HEAD_MAX || s->segments >= STREAM_MAX_SEGMENTS)
        s->done = true;
    if (s->done)
        stream_release(t, s);
    return 1;
}

static void stream_add(flow_table_t *t, flow_t *f, int dir, packet_t *pkt)
{
    stream_t *s = &f->stream[dir];
    uint32_t seq = pkt->tcp_seq;

    if (pkt->tcp_flags & TCPF_SYN) {             /* the SYN itself uses one sequence number */
        if (!s->have_base) {
            s->have_base = true;
            s->base_seq = seq + 1;
        }
        seq += 1;
    }
    if (pkt->payload_len == 0)
        return;
    if (!s->have_base) {                         /* no SYN seen: start where we came in */
        s->have_base = true;
        s->base_seq = seq;
    }

    /* Retransmission: all of this segment's data lies at or below sequence
     * numbers we've already seen. (An out-of-order segment filling a gap
     * also ends below the highest seq, but it adds new bytes to the head
     * buffer, which head_add reports.) */
    uint32_t end = seq + pkt->payload_len;
    bool covered = s->have_max && seq_le(end, s->max_end);
    if (!s->have_max || !seq_le(end, s->max_end)) {
        s->have_max = true;
        s->max_end = end;
    }
    if (head_add(t, f, s, pkt, seq) != 1 && covered) {
        pkt->retransmission = true;
        t->st.retransmissions++;
    }
}

/* ------------------------------------------------------------------------ */
/* Per-connection application context                                       */
/* ------------------------------------------------------------------------ */

/* Copy with truncation, never splitting a UTF-8 character: cutting one in
 * half would produce invalid UTF-8 in our output. */
static void copy_str(char *dst, size_t n, const char *src)
{
    size_t k = strnlen(src, n - 1);
    if (k == n - 1)
        while (k > 0 && ((unsigned char)src[k] & 0xC0) == 0x80)
            k--;                                 /* back up to a character start */
    memcpy(dst, src, k);
    dst[k] = '\0';
}

static void app_context(flow_t *f, int dir, packet_t *pkt)
{
    app_t *a = &pkt->app;

    if (!f->label[0]) {
        if (a->type == APP_TLS_CLIENT_HELLO && a->tls_sni[0])
            copy_str(f->label, sizeof f->label, a->tls_sni);
        else if (a->type == APP_HTTP_REQUEST && a->http_host[0])
            copy_str(f->label, sizeof f->label, a->http_host);
        else if (a->type == APP_DNS && a->dns_has_question)
            copy_str(f->label, sizeof f->label, a->dns_qname);
        else if (a->cred_user[0] && a->type >= APP_FTP)
            snprintf(f->label, sizeof f->label, "%s login: %.64s",
                     a->type == APP_FTP ? "FTP" : a->type == APP_POP3 ? "POP3" : "IMAP",
                     a->cred_user);
    }

    /* FTP and POP3 send the username and password in separate commands.
     * Remember the USER so the PASS can be reported as a complete login. */
    if ((a->type == APP_FTP || a->type == APP_POP3) && dir == 0) {
        if (strcmp(a->cmd, "USER") == 0) {
            copy_str(f->ftp_user, sizeof f->ftp_user, a->cred_user);
        } else if (strcmp(a->cmd, "PASS") == 0 && f->ftp_user[0]) {
            copy_str(a->cred_user, sizeof a->cred_user, f->ftp_user);
            a->cred = CRED_USERPASS;
            a->cred_paired = true;
        }
    }

    /* Match an HTTP response to the request before it on this connection. */
    if (a->type == APP_HTTP_REQUEST) {
        char req[sizeof a->http_method + 1 + sizeof a->http_uri];
        size_t m = strlen(a->http_method);
        memcpy(req, a->http_method, m);
        req[m] = ' ';
        copy_str(req + m + 1, sizeof req - m - 1, a->http_uri);
        copy_str(f->last_request, sizeof f->last_request, req);
    } else if (a->type == APP_HTTP_RESPONSE && f->last_request[0]) {
        copy_str(a->http_request_for, sizeof a->http_request_for, f->last_request);
        f->last_request[0] = '\0';
    }
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

flow_table_t *flow_table_new(unsigned max_flows, unsigned report_n)
{
    flow_table_t *t = calloc(1, sizeof *t);
    if (!t)
        return NULL;
    t->max_flows = max_flows ? max_flows : FLOW_DEFAULT_MAX;
    t->nbuckets = 1024;
    while (t->nbuckets < t->max_flows && t->nbuckets < (1u << 22))
        t->nbuckets <<= 1;
    t->buckets = calloc(t->nbuckets, sizeof *t->buckets);
    if (!t->buckets) {
        free(t);
        return NULL;
    }
    t->report_n = report_n;
    random_key(t->key);
    return t;
}

void flow_update(flow_table_t *t, packet_t *pkt)
{
    if (pkt->l4 != L4_TCP && pkt->l4 != L4_UDP)
        return;

    expire_idle(t, &pkt->ts);

    size_t bucket = flow_hash(t, pkt->ip_proto, pkt->src_ip, pkt->src_port,
                              pkt->dst_ip, pkt->dst_port) & (t->nbuckets - 1);
    int dir = 0;
    flow_t *f = flow_lookup(t, pkt, bucket, &dir);

    /* A fresh SYN on a finished connection is a new connection reusing the
     * same ports: close out the old one. */
    bool syn_only = pkt->l4 == L4_TCP && (pkt->tcp_flags & TCPF_SYN) && !(pkt->tcp_flags & TCPF_ACK);
    if (f && syn_only && (f->state == TCP_CLOSED || f->state == TCP_CLOSING)) {
        t->st.port_reuse++;
        flow_remove(t, f);
        f = NULL;
    }
    if (!f) {
        if (!(f = flow_create(t, pkt, bucket)))
            return;
        dir = (f->cli_ip.s_addr == pkt->src_ip.s_addr && f->cli_port == pkt->src_port) ? 0 : 1;
    }

    f->last = pkt->ts;
    f->pkts[dir]++;
    f->bytes[dir] += pkt->wirelen;
    lru_unlink(t, f);
    lru_append(t, f);

    if (pkt->l4 == L4_TCP) {
        tcp_track(t, f, dir, pkt->tcp_flags);
        stream_add(t, f, dir, pkt);
    }
    app_context(f, dir, pkt);
}

void flow_finish(flow_table_t *t)
{
    while (t->lru_head)
        flow_remove(t, t->lru_head);
}

void flow_table_free(flow_table_t *t)
{
    if (!t)
        return;
    flow_finish(t);
    for (flow_t *f = t->free_list, *next; f; f = next) {
        next = f->hnext;
        free(f);
    }
    free(t->buckets);
    free(t->report);
    free(t);
}

const flow_stats_t *flow_stats(const flow_table_t *t) { return &t->st; }
unsigned long long flow_active(const flow_table_t *t) { return t->active; }

const char *tcp_state_name(tcp_state_t s)
{
    switch (s) {
    case TCP_SYN_SENT:     return "SYN sent";
    case TCP_SYN_RECEIVED: return "SYN received";
    case TCP_ESTABLISHED:  return "established";
    case TCP_CLOSING:      return "closing";
    case TCP_CLOSED:       return "closed";
    case TCP_MIDSTREAM:    return "mid-stream";
    default:               return "-";
    }
}

static const char *human_bytes(uint64_t b, char *buf, size_t n)
{
    if (b < 1024)
        snprintf(buf, n, "%llu B", (unsigned long long)b);
    else if (b < 1024 * 1024)
        snprintf(buf, n, "%.1f KB", b / 1024.0);
    else
        snprintf(buf, n, "%.1f MB", b / (1024.0 * 1024.0));
    return buf;
}

void flow_print_report(const flow_table_t *t, FILE *out, bool tsv)
{
    flow_summary_t *r = t->report;
    qsort(r, t->nreport, sizeof *r, summary_cmp);

    if (!tsv)
        fprintf(out, "\n--- Top %zu conversations by bytes (of %llu) ---\n"
                     "  %-5s %-21s    %-21s %8s %10s %9s  %-12s %s\n",
                t->nreport, t->st.tcp_flows + t->st.udp_flows,
                "proto", "client", "server", "packets", "bytes", "duration", "state", "about");

    for (size_t i = 0; i < t->nreport; i++) {
        const flow_summary_t *s = &r[i];
        char c[INET_ADDRSTRLEN], sv[INET_ADDRSTRLEN], cl[32], sr[32], hb[32];
        inet_ntop(AF_INET, &s->cli_ip, c, sizeof c);
        inet_ntop(AF_INET, &s->srv_ip, sv, sizeof sv);
        const char *proto = s->proto == IPPROTO_TCP ? "TCP" : "UDP";
        double dur = (double)(s->last.tv_sec - s->first.tv_sec) +
                     (s->last.tv_usec - s->first.tv_usec) / 1e6;

        if (tsv) {
            fprintf(out, "flow\t%s\t%s\t%u\t%s\t%u\t%llu\t%llu\t%llu\t%llu\t%.6f\t%s\t%s\n",
                    proto, c, s->cli_port, sv, s->srv_port,
                    (unsigned long long)s->pkts[0], (unsigned long long)s->bytes[0],
                    (unsigned long long)s->pkts[1], (unsigned long long)s->bytes[1],
                    dur, s->proto == IPPROTO_TCP ? tcp_state_name(s->state) : "",
                    s->label);
            continue;
        }
        snprintf(cl, sizeof cl, "%s:%u", c, s->cli_port);
        snprintf(sr, sizeof sr, "%s:%u", sv, s->srv_port);
        fprintf(out, "  %-5s %-21s -> %-21s %8llu %10s %8.2fs  %-12s %s\n",
                proto, cl, sr, (unsigned long long)(s->pkts[0] + s->pkts[1]),
                human_bytes(total_bytes(s), hb, sizeof hb), dur,
                tcp_state_name(s->state), s->label);
    }
}
