#include <linux/bpf.h>
#include <linux/in.h>

#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/pkt_cls.h>
#include <sys/cdefs.h>

#include "parsing_helpers.h"

#ifndef memcpy
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#endif

#define TCPOPT_EOL 0
#define TCPOPT_NOP 1
#define TCPOPT_TIMESTAMP 8
#define TCPOLEN_TIMESTAMP 10
#define MAX_OPT_LEN 12

#define get_key_bit(x) (((x) >> 8) & 1)
#define get_key_index(x) ((x) & 0xFF)

#define MESSAGE_SIZE 32
#define OCCUPATION 3

/*
*
*/
static __always_inline int get_tsval(struct tcphdr *tcph, __u32 **tsval, void *data_end) {
    // 
    if (((void *)tcph) + sizeof(struct tcphdr) + MAX_OPT_LEN > data_end) {
        return -1;
    }
    __u8 *options = (void *)tcph + sizeof(struct tcphdr);
    __u8 kind = options[2];
    __u8 len = options[3];
    if (kind != TCPOPT_TIMESTAMP || len != TCPOLEN_TIMESTAMP) {
        return -1;
    }
    *tsval = (__u32 *)(options + 4);
    return 0;
}

/*
*
*/
SEC("classifier")
int tcp_censor(struct __sk_buff *skb)
{
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data; 
  struct hdr_cursor nh = {.pos = data};
  int eth_type, ip_type, ret = TC_ACT_OK;

  
  
}
