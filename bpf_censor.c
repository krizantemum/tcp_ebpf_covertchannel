#include <linux/bpf.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>

#include "parsing_helpers.h"

#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10
#define MAX_OPT_LEN 12

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
* Attach at tc ingress/egress
*/
SEC("classifier")
int tcp_censor(struct __sk_buff *skb)
{
    // pointer to last byte
    void *data_end = (void *)(long)skb->data_end;
    
    // pointer to first byte
    void *data = (void *)(long)skb->data; 
    
    struct hdr_cursor nh = {.pos = data};
    int eth_type, ip_type, ret = TC_ACT_OK;

    // Protocol headers
    struct iphdr *iphdr;
    struct tcphdr *tcph;
    struct ethhdr *eth;
    
    if (data + sizeof(*eth) > data_end)
        goto out;

    eth_type = parse_ethhdr(&nh, data_end, &eth);
    if (eth_type < 0)
        goto out;

    if (eth_type == bpf_htons(ETH_P_IP)) {
        ip_type = parse_iphdr(&nh, data_end, &iphdr);
    }
    else {
        goto out;
    }

    if (ip_type == IPPROTO_TCP) {

        if (parse_tcphdr(&nh, data_end, &tcph) < 0)
            goto out;
        
        __u32 *tsval;

        // NOP NOP TSval
        if (get_tsval(tcph, &tsval, data_end) == 0) {

            __u32 old = *tsval;
            __u32 host = bpf_ntohl(old);

            host &= ~1;   // zero LSB

            __u32 new = bpf_htonl(host);

            // change checksum if lsb is changed
            if (old != new) {
                *tsval = new;

                bpf_l4_csum_replace(
                    skb,
                    offsetof(struct tcphdr, check),
                    old,
                    new,
                    BPF_F_PSEUDO_HDR | sizeof(__u32)
                );
            }
            else {
                goto out;
            }
}
  out:
      return ret;
}
char _license[] SEC("license") = "GPL";
