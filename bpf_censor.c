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
