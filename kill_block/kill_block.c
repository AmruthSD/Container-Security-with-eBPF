#include "../ptrace_block/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define EPERM 1

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgroup_filter SEC(".maps");

SEC("lsm/task_kill")
int BPF_PROG(block_cross_container_kill,
             struct task_struct *target,
             struct kernel_siginfo *info,
             int sig,
             const struct cred *cred)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();
    __u64 current_cgid = bpf_get_current_cgroup_id();
    __u8 *enabled = bpf_map_lookup_elem(&cgroup_filter, &current_cgid);

    if (!enabled)
        return 0;

    __u64 target_cgid = BPF_CORE_READ(target, cgroups, dfl_cgrp, kn, id);

    if (current_cgid != target_cgid)
    {
        bpf_printk("BLOCK: signal=%d cross-cgroup current=%llu target=%llu\n",
                   sig, current_cgid, target_cgid);
        return -EPERM;
    }

    struct pid_namespace *current_ns = BPF_CORE_READ(current_task, nsproxy, pid_ns_for_children);
    struct pid_namespace *target_ns = BPF_CORE_READ(target, nsproxy, pid_ns_for_children);

    if (current_ns != target_ns)
    {
        bpf_printk("BLOCK: signal=%d cross-pid-namespace cgid=%llu\n", sig, current_cgid);
        return -EPERM;
    }

    bpf_printk("ALLOW: signal=%d same cgroup and pid namespace cgid=%llu\n", sig, current_cgid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
