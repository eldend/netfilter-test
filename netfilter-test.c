#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <regex.h>

char *block_host = NULL;

int check_host(unsigned char *data, int size) {
    struct iphdr *iph = (struct iphdr *)data;
    if (iph->protocol != IPPROTO_TCP) return 0;

    int ip_hdr_len = iph->ihl * 4;
    struct tcphdr *tcph = (struct tcphdr *)(data + ip_hdr_len);
    int tcp_hdr_len = tcph->doff * 4;
    int http_offset = ip_hdr_len + tcp_hdr_len;

    if (size <= http_offset) return 0;

    char *http = (char *)(data + http_offset);

    regex_t regex;
    regmatch_t matches[2];
    const char *pattern = "Host: ([^\r\n]+)";

    if (regcomp(&regex, pattern, REG_EXTENDED | REG_ICASE) != 0) {
        return 0;
    }

    int result = regexec(&regex, http, 2, matches, 0);
    if (result == 0) {
        int start = matches[1].rm_so;
        int end = matches[1].rm_eo;
        int len = end - start;

        if (len > 0 && len < 256) {
            char host[256] = {0};
            strncpy(host, http + start, len);
            host[len] = '\0';

            printf("Host: %s\n", host);
            regfree(&regex);
            return strcmp(host, block_host) == 0;
        }
    }

    regfree(&regex);
    return 0;
}

static u_int32_t print_pkt(struct nfq_data *tb) {
    int id = 0;
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
    }
    return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data) {
    u_int32_t id = print_pkt(nfa);
    unsigned char *pkt_data;
    int len = nfq_get_payload(nfa, &pkt_data);
    if (len >= 0) {
        if (check_host(pkt_data, len)) {
            return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
        }
    }
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <blocked_host>\n", argv[0]);
        exit(1);
    }

    block_host = argv[1];

    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("nfq_open");
        exit(1);
    }

    if (nfq_unbind_pf(h, AF_INET) < 0 || nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind/unbind_pf");
        nfq_close(h);
        exit(1);
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, 0, &cb, NULL);
    if (!qh || nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_create_queue or set_mode");
        nfq_close(h);
        exit(1);
    }

    int fd = nfq_fd(h);
    char buf[4096] __attribute__((aligned));

    while (1) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
        } else if (errno == ENOBUFS) {
            continue;
        } else {
            perror("recv failed");
            break;
        }
    }

    nfq_destroy_queue(qh);
    nfq_close(h);
    return 0;
}
