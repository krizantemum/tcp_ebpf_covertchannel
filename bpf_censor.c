#include <linux/bpf.h>
// #include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
// #include <sys/cdefs.h>

#include "parsing_helpers.h"

/*Most not needed for specialized case, delete*/
#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10
#define MAX_OPT_LEN 12

#define MESSAGE_SIZE 32
#define OCCUPATION 3

/*
*
*/
static __always_inline int get_tsval(struct tcphdr *tcph, __u32 **tsval, void *data_end) {
    // Preventing out of bounds access
    if (((void *)tcph) + sizeof(struct tcphdr) + MAX_OPT_LEN > data_end) {
        return -1;
    }
    // Start of options
    __u8 *options = (void *)tcph + sizeof(struct tcphdr);
    // Yusuf's assumption, delete for universal
    __u8 kind = options[2];
    __u8 len = options[3];
    // Opt is Timestamp and length is OK
    if (kind != TCPOPT_TIMESTAMP || len != TCPOLEN_TIMESTAMP) {
        return -1;
    }
    // Assumption: NOP(1) NOP(1) KIND(1) Length(1)
    *tsval = (__u32 *)(options + 4);
    return 0;
}

/*
* Attaches tc ingress/egress
*/
SEC("classifier")
int tcp_censor(struct __sk_buff *skb)
{
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data; 
    struct hdr_cursor nh = {.pos = data};
    int eth_type, ip_type, ret = TC_ACT_OK;

    // Protocol headers
    struct iphdr *iphdr;
    struct tcphdr *tcph;
    struct ethhdr *eth;

  
}
