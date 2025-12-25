#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>

char message[32] = {0};

uint32_t crc32(const unsigned char *data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc ^= data[i];
        for (int j = 0; j < 8; j++) {
            int mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    return ~crc;
}

uint32_t *get_tsval(struct tcphdr *tcph) {
    int i;
    unsigned int tcp_header_len;
    unsigned int options_len;
    unsigned char *options;
    unsigned char kind;
    unsigned int option_len;
    uint32_t *tsval;

    if (tcph->doff <= 5)
        return NULL;

    options = (unsigned char *)tcph + 20;
    tcp_header_len = (unsigned int)tcph->doff * 4;
    options_len = tcp_header_len - 20;

    i = 0;
    while (i < options_len) {
        kind = options[i];
        if (kind == TCPOPT_EOL)
            break;
        else if (kind == TCPOPT_NOP) {
            i++;
            continue;
        }
        else {
            if (i + 1 >= options_len)
                break;
            option_len = options[i + 1];
            if (kind == TCPOPT_TIMESTAMP && option_len == 10) {
                tsval = (uint32_t *)(options + i + 2);
                return tsval;
            }
            i += option_len;
        }
    }
    return NULL;
}

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    struct iphdr *ip = (struct iphdr *)(bytes + sizeof(struct ethhdr));
    struct tcphdr *tcph = (struct tcphdr *)(bytes + sizeof(struct ethhdr) + ip->ihl * 4);
    if (tcph->syn || tcph->fin || tcph->rst)
        return;
    unsigned char bit_index;
    unsigned char key_bit;
    unsigned char plain_text_bit;
    unsigned char cipher_text_bit;
    uint32_t tsval;
    uint32_t crc;

    tcph->check = 0;
    uint32_t digest = crc32((unsigned char *)tcph, sizeof(struct tcphdr));
    bit_index = digest & 0xFF;
    key_bit = (digest >> 8) & 0x01;
    tsval = ntohl(*get_tsval(tcph));
    if (!tsval) {
        fprintf(stderr, "Failed to get timestamp value.\n");
        return;
    }
    cipher_text_bit = tsval & 0x01;
    plain_text_bit = key_bit ^ cipher_text_bit;
    size_t byte_idx = bit_index / 8;
    uint8_t bit_pos = 7 - (bit_index % 8);
    uint8_t mask = (1u << bit_pos);
    // printf("TCP packet: seq=%u\n", ntohl(tcph->seq));
    // printf("TCP header CRC32: %u\n", digest);
    // printf("TCP timestamp value: %u\n", tsval);
    // printf("Bit index: %u, Key bit: %u, Plain text bit: %u, Hashed bit: %u\n", bit_index, key_bit, plain_text_bit,
    //        cipher_text_bit);
    pthread_mutex_lock(&mutex);
    message[byte_idx] = (message[byte_idx] & ~mask) | ((plain_text_bit << bit_pos) & mask);
    pthread_mutex_unlock(&mutex);
    crc = crc32((unsigned char *)message, 28);
    if (crc != 0 && (memcmp((uint32_t *)(message + 28), &crc, sizeof(uint32_t)) == 0)) {
        printf("%.28s", message);
        fflush(stdout);
        memset(message, 0, sizeof(message));
    }
    // printf("Current message: %.28s\n", message);
}

int main(int argc, char *argv[]) {

    char *dev;
    if (argc > 1) {
        dev = argv[1];
    }
    else {
        dev = "ifb0";
    }
#include <ifaddrs.h>
#include <arpa/inet.h>

    char dev_ip[INET_ADDRSTRLEN] = {0};
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        return 1;
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;
        if (ifa->ifa_addr->sa_family == AF_INET && strcmp(ifa->ifa_name, dev) == 0) {
            struct sockaddr_in *sa = (struct sockaddr_in *)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &sa->sin_addr, dev_ip, sizeof(dev_ip)) != NULL) {
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    if (dev_ip[0] == '\0') {
        fprintf(stderr, "Failed to get IPv4 address for interface %s\n", dev);
        return 1;
    }
    printf("Interface %s IP: %s\n", dev, dev_ip);
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    // pcap_dumper_t *dumper;
    // const char *outfile = "capture.pcap";

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    // dumper = pcap_dump_open(handle, outfile);
    // if (!dumper) {
    //     fprintf(stderr, "pcap_dump_open failed: %s\n", pcap_geterr(handle));
    //     pcap_close(handle);
    //     return 1;
    // }

    struct bpf_program fp;
    //    char filter_exp[64];
    char filter_exp[64];
    if (snprintf(filter_exp, sizeof(filter_exp), "tcp and ip dst host %s", dev_ip) >= (int)sizeof(filter_exp)) {
        fprintf(stderr, "Filter expression too long\n");
        return 1;
    }
    if (pcap_compile(handle, &fp, filter_exp, 1, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile failed: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter failed: %s\n", pcap_geterr(handle));
        pcap_freecode(&fp);
        return 1;
    }
    pcap_freecode(&fp);
    printf("Filter applied: %s\n", filter_exp);
    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1 || pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Failed to set filter.\n");
        return 1;
    }

    printf("Listening on interface %s for TCP packets...\n", dev);
    pcap_loop(handle, -1, packet_handler, NULL);

    pcap_close(handle);
    return 0;
}
