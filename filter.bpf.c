
#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#define PROCESS_NAME "myprocess"
#define DEFAULT_PORT 4040

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} allowed_port SEC(".maps");

SEC("cgroup/connect4")
int filter_process(struct bpf_sock_addr *ctx)
{
    char comm[16] = {};
    __u32 key = 0;
    __u32 *port;

    /* Ignore processes other than myprocess */
    if (bpf_get_current_comm(comm, sizeof(comm)) != 0)
        return 1;

    if (__builtin_strncmp(comm, PROCESS_NAME,
                          sizeof(PROCESS_NAME)) != 0)
        return 1;

    /* Only filter TCP connection attempts */
    if (ctx->protocol != IPPROTO_TCP)
        return 1;

    port = bpf_map_lookup_elem(&allowed_port, &key);

    if (!port)
        return 0;

    /* Allow only the configured destination port */
    if (bpf_ntohs((__u16)ctx->user_port) == *port)
        return 1;

    /* Block other TCP destination ports for myprocess */
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
