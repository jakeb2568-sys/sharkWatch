/*
 * app.h - application-layer decoding (Stage 3).
 *
 * Everything in a packet payload is attacker-controlled: a hostile DNS server
 * or web client chooses every byte. So every string pulled out of a payload is
 *   - length-limited (fixed-size buffers, always NUL-terminated), and
 *   - sanitized: non-printable bytes become \xNN escapes, so a crafted name
 *     can't inject terminal escape codes into whoever is reading our output.
 *
 * Decoding is per packet. A request split across several TCP segments is
 * only decoded from the segment that holds its start; stream reassembly
 * comes with flow tracking in Stage 4.
 */
#ifndef SHARKWATCH_APP_H
#define SHARKWATCH_APP_H

#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>

#define APP_STR_MAX   256
#define DNS_MAX_ADDRS 8

typedef enum {
    APP_NONE = 0,
    APP_DNS,                /* UDP 53 (DNS), 5353 (mDNS), 5355 (LLMNR) */
    APP_HTTP_REQUEST,       /* recognised by content, on any TCP port */
    APP_HTTP_RESPONSE,
    APP_TLS_CLIENT_HELLO,   /* first message of a TLS handshake */
    APP_FTP,                /* client -> server commands, TCP 21 */
    APP_POP3,               /* TCP 110 */
    APP_IMAP,               /* TCP 143 */
} app_type_t;

typedef enum {
    CRED_NONE = 0,
    CRED_USER,              /* username only (FTP/POP3 USER) */
    CRED_PASS,              /* password only (FTP/POP3 PASS) */
    CRED_USERPASS,          /* both in one message (HTTP Basic, IMAP LOGIN) */
} cred_kind_t;

typedef struct {
    app_type_t type;

    /* DNS */
    uint16_t dns_id;
    bool     dns_response;
    uint8_t  dns_rcode;
    bool     dns_has_question;
    char     dns_qname[APP_STR_MAX];
    uint16_t dns_qtype;
    uint16_t dns_answers;                   /* ANCOUNT from the header */
    struct in_addr dns_addrs[DNS_MAX_ADDRS];/* A records, in packet order */
    int      dns_addr_count;

    /* HTTP */
    char     http_method[16];
    char     http_uri[APP_STR_MAX];
    char     http_host[APP_STR_MAX];
    uint16_t http_status;
    char     http_reason[64];

    /* TLS ClientHello */
    char     tls_sni[APP_STR_MAX];          /* Server Name Indication */
    char     tls_alpn[32];                  /* first ALPN protocol offered */
    bool     tls_partial;                   /* hello continues in a later segment */
    bool     tls_retry;                     /* second hello, after a HelloRetryRequest */

    /* FTP / POP3 / IMAP command line */
    char     cmd[16];
    char     cmd_arg[APP_STR_MAX];

    /* Cleartext credentials */
    cred_kind_t cred;
    char     cred_user[APP_STR_MAX];
    char     cred_pass[APP_STR_MAX];
} app_t;

struct packet;

/* Decode the payload of an already-decoded TCP/UDP packet. Returns 0 on
 * success (including "not a protocol we know"), -1 if the payload claimed to
 * be a protocol we decode but was malformed (pkt->error says why). */
int decode_app(struct packet *pkt);

#endif
