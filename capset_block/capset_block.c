#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct {
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
        return 1;
    return 0;
}

SEC("lsm/capset")
int BPF_PROG(block_capset,
             struct cred *new,
             const struct cred *old,
             const struct kernel_cap_struct *effective,
             const struct kernel_cap_struct *inheritable,
             const struct kernel_cap_struct *permitted)
{
    if (!is_container())
        return 0;

    bpf_printk("BLOCK: capset syscall\n");
    return -EPERM;
}

char LICENSE[] SEC("license") = "GPL";
