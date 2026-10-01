/*
 * wirewatch - a small packet analyzer built on libpcap.
 *
 * Stage 0: open a capture (live interface or .pcap file) and report the
 * size of every packet. No parsing yet.
 */
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static void on_packet(u_char *user, const struct pcap_pkthdr *hdr,
                      const u_char *bytes)
{
    (void)bytes;
    unsigned long *count = (unsigned long *)user;
    (*count)++;
    printf("%5lu  captured %u of %u bytes\n", *count, hdr->caplen, hdr->len);
}

int main(int argc, char **argv)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    const char *file = NULL, *iface = NULL;
    int opt;

    while ((opt = getopt(argc, argv, "r:i:")) != -1) {
        switch (opt) {
        case 'r': file = optarg; break;
        case 'i': iface = optarg; break;
        default:
            fprintf(stderr, "usage: %s -r file.pcap | -i interface\n", argv[0]);
            return EXIT_FAILURE;
        }
    }

    pcap_t *handle = file ? pcap_open_offline(file, errbuf)
                   : iface ? pcap_open_live(iface, 65535, 1, 1000, errbuf)
                   : NULL;
    if (!handle) {
        fprintf(stderr, "%s\n", (file || iface) ? errbuf
                : "usage: wirewatch -r file.pcap | -i interface");
        return EXIT_FAILURE;
    }

    unsigned long count = 0;
    pcap_loop(handle, -1, on_packet, (u_char *)&count);
    pcap_close(handle);
    return EXIT_SUCCESS;
}
