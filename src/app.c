/*
 * app.c - application-layer decoders: DNS, HTTP, TLS ClientHello, and the
 * plaintext login commands of FTP / POP3 / IMAP.
 *
 * Ground rules (see app.h): payload bytes are hostile. Work on (pointer,
 * length) ranges, never assume a NUL terminator, bound every loop, and
 * sanitize every string before it leaves this file.
 */
#include "app.h"
#include "decode.h"

#include <ctype.h>
#include <string.h>
#include <strings.h>

/* ------------------------------------------------------------------------ */
/* Small helpers                                                            */
/* ------------------------------------------------------------------------ */

/* Read big-endian integers byte by byte. Works at any alignment and on any
 * host byte order: an alternative to memcpy + ntohs() for short fields. */
static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] << 8 | p[1]); }

static int fail(packet_t *pkt, const char *why)
{
    pkt->error = why;
    return -1;
}

/* Is in[0..n) the start of a UTF-8 character that's safe to show as-is?
 * Returns its length in bytes (2-4), or 0 if it should be escaped instead.
 *
 * Real-world names are often not ASCII ("Jake’s iPhone" has a 3-byte curly
 * apostrophe), so valid UTF-8 is passed through. Rejected:
 *   - invalid or "overlong" encodings and UTF-16 surrogates: malformed input
 *     that different decoders interpret differently;
 *   - C1 control characters (U+0080..U+009F): some terminals obey them;
 *   - invisible and text-direction characters (zero-width spaces, bidi
 *     overrides like U+202E). These are the "Trojan Source" trick
 *     (CVE-2021-42574): U+202E can make "exe.gnp" display as "png.exe".  */
static size_t utf8_safe_len(const uint8_t *in, size_t n)
{
    uint32_t cp;
    size_t len;
    uint8_t c = in[0];

    if (c >= 0xC2 && c <= 0xDF)      { len = 2; cp = c & 0x1F; }
    else if (c >= 0xE0 && c <= 0xEF) { len = 3; cp = c & 0x0F; }
    else if (c >= 0xF0 && c <= 0xF4) { len = 4; cp = c & 0x07; }
    else return 0;          /* 0x80-0xC1, 0xF5-0xFF never start a valid character */

    if (len > n)
        return 0;
    for (size_t i = 1; i < len; i++) {
        if ((in[i] & 0xC0) != 0x80)
            return 0;
        cp = cp << 6 | (in[i] & 0x3F);
    }
    if ((len == 3 && cp < 0x800) || (len == 4 && (cp < 0x10000 || cp > 0x10FFFF)))
        return 0;                                   /* overlong / out of range */
    if (cp >= 0xD800 && cp <= 0xDFFF)
        return 0;                                   /* UTF-16 surrogate halves */
    if (cp <= 0x9F)
        return 0;                                   /* C1 controls */
    if ((cp >= 0x200B && cp <= 0x200F) || (cp >= 0x2028 && cp <= 0x202E) ||
        (cp >= 0x2066 && cp <= 0x2069) || cp == 0x061C || cp == 0xFEFF)
        return 0;                                   /* invisible / bidi controls */
    return len;
}

/* Append bytes to a NUL-terminated buffer, escaping anything unsafe as \xNN,
 * and silently truncating at the buffer's end (never mid-character).
 * Printable ASCII and safe UTF-8 pass through; control bytes, invalid UTF-8
 * and invisible/bidi characters don't. This is what keeps a hostile
 * "\x1b[2J" in a DNS name from clearing your terminal when it's printed. */
static void append_safe(char *out, size_t outsz, const uint8_t *in, size_t n)
{
    static const char hex[] = "0123456789abcdef";
    size_t len = strlen(out);

    for (size_t i = 0; i < n && len + 1 < outsz; i++) {
        uint8_t c = in[i];
        if (c >= 0x20 && c < 0x7f && c != '\\') {
            out[len++] = (char)c;
            continue;
        }
        size_t k = c >= 0x80 ? utf8_safe_len(in + i, n - i) : 0;
        if (k) {
            if (len + k >= outsz)
                break;
            memcpy(out + len, in + i, k);
            len += k;
            i += k - 1;
            continue;
        }
        if (len + 4 >= outsz)
            break;
        out[len++] = '\\';
        out[len++] = 'x';
        out[len++] = hex[c >> 4];
        out[len++] = hex[c & 0xF];
    }
    out[len] = '\0';
}

static void copy_safe(char *out, size_t outsz, const uint8_t *in, size_t n)
{
    out[0] = '\0';
    append_safe(out, outsz, in, n);
}

/* Length of the first line in [p, p+n): up to but not including \r\n or \n.
 * *complete says whether we actually found the line ending. */
static size_t line_length(const uint8_t *p, size_t n, bool *complete)
{
    for (size_t i = 0; i < n; i++) {
        if (p[i] == '\n') {
            *complete = true;
            return (i > 0 && p[i - 1] == '\r') ? i - 1 : i;
        }
    }
    *complete = false;
    return n;
}

static bool starts_with(const uint8_t *p, size_t n, const char *s)
{
    size_t k = strlen(s);
    return n >= k && memcmp(p, s, k) == 0;
}

static bool starts_with_nocase(const uint8_t *p, size_t n, const char *s)
{
    size_t k = strlen(s);
    return n >= k && strncasecmp((const char *)p, s, k) == 0;
}

/* Index of the first byte in [p, p+n) equal to c, or n if absent. */
static size_t find_byte(const uint8_t *p, size_t n, uint8_t c)
{
    const uint8_t *hit = memchr(p, c, n);
    return hit ? (size_t)(hit - p) : n;
}

static size_t skip_spaces(const uint8_t *p, size_t n, size_t i)
{
    while (i < n && (p[i] == ' ' || p[i] == '\t'))
        i++;
    return i;
}

/* ------------------------------------------------------------------------ */
/* DNS (RFC 1035)                                                           */
/* ------------------------------------------------------------------------ */

#define DNS_HDR_LEN    12
#define DNS_MAX_JUMPS  64    /* compression pointers followed per name */
#define DNS_MAX_NAME   255   /* RFC 1035 limit on a name's wire length */

enum { DNS_OK = 0, DNS_TRUNCATED, DNS_LOOP, DNS_BAD_LABEL, DNS_TOO_LONG };

static const char *dns_error(int e)
{
    switch (e) {
    case DNS_TRUNCATED: return "truncated DNS name";
    case DNS_LOOP:      return "DNS name compression loop";
    case DNS_BAD_LABEL: return "bad DNS label type";
    default:            return "DNS name too long";
    }
}

/*
 * Read a (possibly compressed) domain name starting at msg[off].
 *
 * A name is a series of length-prefixed labels ending in a zero byte:
 *     \x03www\x07example\x03com\x00
 * To save space, a label can instead be a 2-byte "pointer" (top two bits
 * set) to a name earlier in the message. A hostile packet can make a pointer
 * point at itself, or two pointers point at each other, so a naive decoder
 * loops forever. We cap the number of jumps and the total name length.
 *
 * *next is set to the offset just past the name *in the original position*,
 * i.e. after the first pointer if there was one, which is where the next
 * field of the record begins.
 */
static int dns_read_name(const uint8_t *msg, size_t len, size_t off,
                         char *out, size_t outsz, size_t *next)
{
    size_t pos = off, wire_len = 0;
    int jumps = 0;
    bool jumped = false;

    out[0] = '\0';
    for (;;) {
        if (pos >= len)
            return DNS_TRUNCATED;
        uint8_t l = msg[pos];

        if ((l & 0xC0) == 0xC0) {                 /* compression pointer */
            if (pos + 1 >= len)
                return DNS_TRUNCATED;
            if (!jumped) {
                *next = pos + 2;
                jumped = true;
            }
            if (++jumps > DNS_MAX_JUMPS)
                return DNS_LOOP;
            pos = (size_t)(l & 0x3F) << 8 | msg[pos + 1];
            continue;
        }
        if (l & 0xC0)                             /* 0x40 / 0x80: obsolete/reserved */
            return DNS_BAD_LABEL;
        if (l == 0) {                             /* end of name */
            if (!jumped)
                *next = pos + 1;
            break;
        }
        if (pos + 1 + l > len)
            return DNS_TRUNCATED;
        wire_len += 1u + l;
        if (wire_len > DNS_MAX_NAME)
            return DNS_TOO_LONG;
        if (out[0] != '\0')
            append_safe(out, outsz, (const uint8_t *)".", 1);
        append_safe(out, outsz, msg + pos + 1, l);
        pos += 1u + l;
    }
    if (out[0] == '\0')
        snprintf(out, outsz, "<Root>");           /* same spelling as Wireshark */
    return DNS_OK;
}

static int decode_dns(packet_t *pkt)
{
    const uint8_t *m = pkt->payload;
    size_t len = pkt->payload_caplen;
    app_t *a = &pkt->app;
    char scratch[APP_STR_MAX];
    size_t off, next = 0;
    int e;

    if (len < DNS_HDR_LEN)
        return fail(pkt, "truncated DNS header");

    uint16_t flags = rd16(m + 2);
    unsigned qd = rd16(m + 4), an = rd16(m + 6), ns = rd16(m + 8), ar = rd16(m + 10);

    a->type         = APP_DNS;
    a->dns_id       = rd16(m);
    a->dns_response = flags & 0x8000;
    a->dns_rcode    = flags & 0x000F;
    a->dns_answers  = (uint16_t)an;
    off = DNS_HDR_LEN;

    /* Questions: name, QTYPE, QCLASS. We keep the first. */
    for (unsigned i = 0; i < qd; i++) {
        char *dst = i == 0 ? a->dns_qname : scratch;
        if ((e = dns_read_name(m, len, off, dst, APP_STR_MAX, &next)) != DNS_OK)
            return fail(pkt, dns_error(e));
        if (next + 4 > len)
            return fail(pkt, "truncated DNS question");
        if (i == 0) {
            a->dns_qtype = rd16(m + next);
            a->dns_has_question = true;
        }
        off = next + 4;
    }

    /* Resource records (answer, authority, additional): name, TYPE, CLASS,
     * TTL (4), RDLENGTH, RDATA. We collect IPv4 addresses from A records.
     * The loop is bounded by the counts *and* by the data: every record
     * consumes at least 11 bytes, so a lying count just runs out of bytes. */
    for (unsigned i = 0; i < an + ns + ar; i++) {
        if ((e = dns_read_name(m, len, off, scratch, sizeof scratch, &next)) != DNS_OK)
            return fail(pkt, dns_error(e));
        if (next + 10 > len)
            return fail(pkt, "truncated DNS record");
        uint16_t type  = rd16(m + next);
        uint16_t rdlen = rd16(m + next + 8);
        off = next + 10;
        if (off + rdlen > len)
            return fail(pkt, "truncated DNS record data");
        if (type == 1 && rdlen == 4 && a->dns_addr_count < DNS_MAX_ADDRS)
            memcpy(&a->dns_addrs[a->dns_addr_count++], m + off, 4);
        off += rdlen;
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Base64 (for HTTP Basic auth)                                             */
/* ------------------------------------------------------------------------ */

static int b64_value(uint8_t c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/* Decode until '=' or the first non-base64 byte. Returns bytes written. */
static size_t b64_decode(const uint8_t *in, size_t n, uint8_t *out, size_t outsz)
{
    uint32_t acc = 0;
    int bits = 0;
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        int v = b64_value(in[i]);
        if (v < 0)
            break;
        acc = (acc << 6 | (uint32_t)v) & 0xFFFFFF;  /* only the low bits matter */
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            if (o < outsz)
                out[o++] = (uint8_t)(acc >> bits);
        }
    }
    return o;
}

/* ------------------------------------------------------------------------ */
/* HTTP/1.x (RFC 9112)                                                      */
/* ------------------------------------------------------------------------ */

static const char *const http_methods[] = {
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
};

static bool looks_like_http_request(const uint8_t *p, size_t n)
{
    for (size_t i = 0; i < sizeof http_methods / sizeof http_methods[0]; i++) {
        size_t k = strlen(http_methods[i]);
        if (starts_with(p, n, http_methods[i]) && n > k && p[k] == ' ')
            return true;
    }
    return false;
}

/* Walk the header lines that follow the start line. Stops at the blank line
 * that ends the headers, or at the end of the captured bytes. */
static void http_headers(packet_t *pkt, const uint8_t *p, size_t n)
{
    app_t *a = &pkt->app;
    size_t off = 0;

    while (off < n) {
        bool complete;
        size_t ll = line_length(p + off, n - off, &complete);
        const uint8_t *line = p + off;
        if (ll == 0)
            break;                                  /* blank line: end of headers */

        size_t colon = find_byte(line, ll, ':');
        if (colon < ll) {
            size_t v = skip_spaces(line, ll, colon + 1);
            const uint8_t *val = line + v;
            size_t vlen = ll - v;

            if (colon == 4 && starts_with_nocase(line, ll, "host")) {
                copy_safe(a->http_host, sizeof a->http_host, val, vlen);
            } else if (colon == 13 && starts_with_nocase(line, ll, "authorization") &&
                       starts_with_nocase(val, vlen, "basic ")) {
                /* "Authorization: Basic base64(user:password)". Base64 is an
                 * encoding, not encryption: anyone on the path can read it. */
                uint8_t raw[APP_STR_MAX];
                size_t s = skip_spaces(val, vlen, 6);
                size_t rn = b64_decode(val + s, vlen - s, raw, sizeof raw);
                size_t sep = find_byte(raw, rn, ':');
                a->cred = CRED_USERPASS;
                copy_safe(a->cred_user, sizeof a->cred_user, raw, sep);
                if (sep < rn)
                    copy_safe(a->cred_pass, sizeof a->cred_pass, raw + sep + 1, rn - sep - 1);
            }
        }
        if (!complete)
            break;
        off += ll;                                  /* to the end of this line... */
        off += (p[off] == '\r') ? 2 : 1;            /* ...and past its CRLF / LF */
    }
}

static int decode_http_request(packet_t *pkt, const uint8_t *p, size_t n)
{
    app_t *a = &pkt->app;
    bool complete;
    size_t ll = line_length(p, n, &complete);

    /* Request line: METHOD SP request-target SP HTTP-version */
    size_t sp1 = find_byte(p, ll, ' ');
    size_t sp2 = sp1 + 1 + find_byte(p + sp1 + 1, ll - sp1 - 1, ' ');
    if (sp2 >= ll || !starts_with(p + sp2 + 1, ll - sp2 - 1, "HTTP/"))
        return 0;                                    /* not really HTTP; ignore */

    a->type = APP_HTTP_REQUEST;
    copy_safe(a->http_method, sizeof a->http_method, p, sp1);
    copy_safe(a->http_uri, sizeof a->http_uri, p + sp1 + 1, sp2 - sp1 - 1);

    if (complete) {
        size_t hdr = ll + ((ll < n && p[ll] == '\r') ? 2 : 1);
        if (hdr < n)
            http_headers(pkt, p + hdr, n - hdr);
    }
    return 0;
}

static int decode_http_response(packet_t *pkt, const uint8_t *p, size_t n)
{
    app_t *a = &pkt->app;
    bool complete;
    size_t ll = line_length(p, n, &complete);

    /* Status line: HTTP-version SP 3DIGIT SP reason */
    size_t sp = find_byte(p, ll, ' ');
    if (sp + 4 > ll || !isdigit(p[sp + 1]) || !isdigit(p[sp + 2]) || !isdigit(p[sp + 3]))
        return 0;

    a->type = APP_HTTP_RESPONSE;
    a->http_status = (uint16_t)((p[sp + 1] - '0') * 100 + (p[sp + 2] - '0') * 10 + (p[sp + 3] - '0'));
    if (sp + 5 <= ll)
        copy_safe(a->http_reason, sizeof a->http_reason, p + sp + 5, ll - sp - 5);
    return 0;
}

/* ------------------------------------------------------------------------ */
/* TLS ClientHello (RFC 8446 section 4.1.2)                                 */
/*                                                                          */
/* The handshake is encrypted from the ServerHello onward, but the client's */
/* first message is plaintext, and its server_name extension (SNI) names    */
/* the site being visited. That's why HTTPS still leaks hostnames.          */
/* ------------------------------------------------------------------------ */

#define TLS_CONTENT_HANDSHAKE 0x16
#define TLS_HS_CLIENT_HELLO   0x01
#define TLS_EXT_SERVER_NAME   0
#define TLS_EXT_ALPN          16

static bool looks_like_client_hello(const uint8_t *p, size_t n)
{
    return n >= 6 && p[0] == TLS_CONTENT_HANDSHAKE && p[1] == 0x03 && p[2] <= 0x04 &&
           p[5] == TLS_HS_CLIENT_HELLO;
}

static void tls_ext_server_name(app_t *a, const uint8_t *e, size_t n)
{
    /* server_name_list length (2), then entries: type (1), length (2), name */
    if (n < 5 || e[2] != 0)                       /* 0 = host_name */
        return;
    size_t nlen = rd16(e + 3);
    if (5 + nlen <= n)
        copy_safe(a->tls_sni, sizeof a->tls_sni, e + 5, nlen);
}

static void tls_ext_alpn(app_t *a, const uint8_t *e, size_t n)
{
    /* protocol_name_list length (2), then entries: length (1), name */
    if (n < 3)
        return;
    size_t plen = e[2];
    if (plen > 0 && 3 + plen <= n)
        copy_safe(a->tls_alpn, sizeof a->tls_alpn, e + 3, plen);
}

static int decode_tls_client_hello(packet_t *pkt, const uint8_t *p, size_t n)
{
    app_t *a = &pkt->app;
    a->type = APP_TLS_CLIENT_HELLO;

    /* Everything we read must lie inside both the TLS record and the bytes we
     * captured. Modern hellos (big post-quantum key shares) often don't fit
     * in one TCP segment; then we decode what's here and mark it partial. */
    size_t end = 5 + (size_t)rd16(p + 3);
    if (end > n) {
        end = n;
        a->tls_partial = true;
    }

#define NEED(x) do { if ((x) > end) { a->tls_partial = true; return 0; } } while (0)

    size_t off = 5 + 4;                 /* record header, handshake header */
    NEED(off + 2 + 32 + 1);
    off += 2 + 32;                      /* legacy_version, random */
    off += 1 + p[off];                  /* session id */
    NEED(off + 2);
    off += 2 + rd16(p + off);           /* cipher suites */
    NEED(off + 1);
    off += 1 + p[off];                  /* compression methods */
    NEED(off + 2);
    size_t ext_end = off + 2 + rd16(p + off);
    off += 2;
    if (ext_end > end) {
        ext_end = end;
        a->tls_partial = true;
    }

    while (off + 4 <= ext_end) {
        uint16_t type = rd16(p + off);
        size_t elen = rd16(p + off + 2);
        off += 4;
        if (off + elen > ext_end) {
            a->tls_partial = true;
            break;
        }
        if (type == TLS_EXT_SERVER_NAME)
            tls_ext_server_name(a, p + off, elen);
        else if (type == TLS_EXT_ALPN)
            tls_ext_alpn(a, p + off, elen);
        off += elen;
    }
#undef NEED
    return 0;
}

/* ------------------------------------------------------------------------ */
/* FTP / POP3 / IMAP: plaintext command protocols                           */
/* ------------------------------------------------------------------------ */

/* Read an IMAP "astring": either "quoted" or a bare atom. */
static size_t imap_astring(const uint8_t *p, size_t n, size_t i, char *out, size_t outsz)
{
    out[0] = '\0';
    if (i < n && p[i] == '"') {
        size_t close = i + 1 + find_byte(p + i + 1, n - i - 1, '"');
        copy_safe(out, outsz, p + i + 1, close - i - 1);
        return close < n ? close + 1 : n;
    }
    size_t sp = i + find_byte(p + i, n - i, ' ');
    copy_safe(out, outsz, p + i, sp - i);
    return sp;
}

static int decode_command(packet_t *pkt, app_type_t proto, const uint8_t *p, size_t n)
{
    app_t *a = &pkt->app;
    bool complete;
    size_t ll = line_length(p, n, &complete);
    size_t i = 0;

    /* Only treat it as a command if the first word is plain letters. */
    if (proto == APP_IMAP) {                        /* "a001 LOGIN user pass" */
        i = find_byte(p, ll, ' ');
        if (i == 0 || i >= ll)
            return 0;
        i++;
    }
    size_t w = i;
    while (w < ll && w - i < sizeof a->cmd - 1 && isalpha(p[w]))
        w++;
    if (w == i || (w < ll && p[w] != ' '))
        return 0;

    a->type = proto;
    copy_safe(a->cmd, sizeof a->cmd, p + i, w - i);
    for (char *c = a->cmd; *c; c++)
        *c = (char)toupper((unsigned char)*c);
    size_t arg = w < ll ? w + 1 : ll;

    if (proto == APP_IMAP) {
        if (strcmp(a->cmd, "LOGIN") == 0) {
            size_t j = imap_astring(p, ll, arg, a->cred_user, sizeof a->cred_user);
            imap_astring(p, ll, skip_spaces(p, ll, j), a->cred_pass, sizeof a->cred_pass);
            a->cred = CRED_USERPASS;
        }
        copy_safe(a->cmd_arg, sizeof a->cmd_arg, p + arg, ll - arg);
        return 0;
    }

    copy_safe(a->cmd_arg, sizeof a->cmd_arg, p + arg, ll - arg);
    if (strcmp(a->cmd, "USER") == 0) {
        a->cred = CRED_USER;
        copy_safe(a->cred_user, sizeof a->cred_user, p + arg, ll - arg);
    } else if (strcmp(a->cmd, "PASS") == 0) {
        a->cred = CRED_PASS;
        copy_safe(a->cred_pass, sizeof a->cred_pass, p + arg, ll - arg);
    }
    return 0;
}

/* ------------------------------------------------------------------------ */
/* Dispatch                                                                 */
/* ------------------------------------------------------------------------ */

static bool either_port(const packet_t *pkt, uint16_t port)
{
    return pkt->src_port == port || pkt->dst_port == port;
}

int decode_app(packet_t *pkt)
{
    const uint8_t *p = pkt->payload;
    size_t n = pkt->payload_caplen;

    if (n == 0 || pkt_is_fragment(pkt))
        return 0;

    if (pkt->l4 == L4_UDP) {
        if (either_port(pkt, 53) || either_port(pkt, 5353) || either_port(pkt, 5355))
            return decode_dns(pkt);
        return 0;
    }

    if (pkt->l4 != L4_TCP)
        return 0;

    /* HTTP and TLS are recognised by their content, so they're found on any
     * port. (A web server on an odd port is itself worth noticing.) */
    if (looks_like_client_hello(p, n))
        return decode_tls_client_hello(pkt, p, n);
    if (looks_like_http_request(p, n))
        return decode_http_request(pkt, p, n);
    if (starts_with(p, n, "HTTP/1."))
        return decode_http_response(pkt, p, n);

    /* Command protocols: only client -> server traffic carries logins. */
    switch (pkt->dst_port) {
    case 21:  return decode_command(pkt, APP_FTP, p, n);
    case 110: return decode_command(pkt, APP_POP3, p, n);
    case 143: return decode_command(pkt, APP_IMAP, p, n);
    default:  return 0;
    }
}
