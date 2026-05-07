#include "../ptrace_block/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define EPERM 1

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgroup_filter SEC(".maps");

static __always_inline int is_container(void)
{
    __u64 cgid = bpf_get_current_cgroup_id();
    __u8 *val = bpf_map_lookup_elem(&cgroup_filter, &cgid);

    if (val && *val)
    {
        bpf_printk("Container found with cgid=%llu", cgid);
        return 1;
    }

    return 0;
}

SEC("lsm/bpf")
int BPF_PROG(block_bpf, int cmd, union bpf_attr *attr, unsigned int size)
{
    if (!is_container())
        return 0;

    bpf_printk("BLOCK: bpf syscall cmd=%d\n", cmd);
    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
