/*
 * proto.h - on-the-wire header layouts.
 *
 * Every multi-byte field is in network byte order (big-endian). Convert with
 * ntohs()/ntohl() before using the value, or you'll read port 80 as 20480.
 *
 * We never point one of these structs directly at packet memory, e.g.
 *     const struct ipv4_hdr *ip = (const void *)(frame + 14);   // don't
 * The IPv4 header starts 14 bytes into an Ethernet frame, so it isn't 4-byte
 * aligned, and reading a misaligned uint32_t is undefined behaviour in C
 * (it crashes outright on some CPUs). Instead the decoder memcpy()s the bytes
 * into a local struct, which is always correctly aligned.
 */
#ifndef WIREWATCH_PROTO_H
#define WIREWATCH_PROTO_H

#include <stdint.h>

/* ---- Ethernet II ------------------------------------------------------- */

#define ETH_ADDR_LEN   6
#define ETH_HDR_LEN    14
#define VLAN_TAG_LEN   4

#define ETYPE_IPV4     0x0800
#define ETYPE_ARP      0x0806
#define ETYPE_VLAN     0x8100   /* 802.1Q tag */
#define ETYPE_QINQ     0x88A8   /* 802.1ad outer tag ("Q-in-Q") */
#define ETYPE_IPV6     0x86DD

struct eth_hdr {
    uint8_t  dst[ETH_ADDR_LEN];
    uint8_t  src[ETH_ADDR_LEN];
    uint16_t ethertype;
};

/* An 802.1Q tag sits where the ethertype would be: TPID (0x8100, already
 * consumed as the "ethertype"), then these 4 bytes. */
struct vlan_tag {
    uint16_t tci;               /* 3 bits priority, 1 bit DEI, 12 bits VLAN ID */
    uint16_t ethertype;         /* the real ethertype of what follows */
};

/* ---- Linux "cooked" capture headers (capturing on -i any) ------------- */

#define SLL_HDR_LEN    16       /* DLT_LINUX_SLL: protocol at offset 14 */
#define SLL2_HDR_LEN   20       /* DLT_LINUX_SLL2: protocol at offset 0 */

/* ---- IPv4 (RFC 791) ---------------------------------------------------- */

#define IPV4_MIN_HDR_LEN  20
#define IPV4_FLAG_DF      0x4000
#define IPV4_FLAG_MF      0x2000
#define IPV4_FRAG_MASK    0x1FFF   /* offset, in 8-byte units */

struct ipv4_hdr {
    uint8_t  ver_ihl;           /* high nibble: version, low nibble: header length in 32-bit words */
    uint8_t  tos;
    uint16_t total_len;         /* header + payload, in bytes */
    uint16_t id;
    uint16_t frag;              /* flags (3 bits) + fragment offset (13 bits) */
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
};

/* The compiler must not insert padding, or our offsets would be wrong. */
_Static_assert(sizeof(struct eth_hdr)  == ETH_HDR_LEN,      "eth_hdr size");
_Static_assert(sizeof(struct vlan_tag) == VLAN_TAG_LEN,     "vlan_tag size");
_Static_assert(sizeof(struct ipv4_hdr) == IPV4_MIN_HDR_LEN, "ipv4_hdr size");

#endif
