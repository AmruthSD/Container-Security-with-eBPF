#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // cgroup id
    __type(value, __u8);
} cgroup_filter SEC(".maps");

SEC("lsm/ptrace_access_check")
int BPF_PROG(block_ptrace, struct task_struct *child, unsigned int mode)
{
    struct task_struct *current_task = (struct task_struct *)bpf_get_current_task();

    __u64 current_cgid = bpf_get_current_cgroup_id();

    // check if this cgroup is monitored
    __u8 *enabled = bpf_map_lookup_elem(&cgroup_filter, &current_cgid);
    if (!enabled)
        return 0;

    bpf_printk("Container with cgid=%llu",current_cgid);

    // CO-RE safe read of child's cgroup id
    __u64 target_cgid = BPF_CORE_READ(child, cgroups, dfl_cgrp, kn, id);

    // block cross-cgroup ptrace
    if (current_cgid != target_cgid){
        bpf_printk("Blocking cause invalid cgroups");
        return -1;
    }

    // PID namespace check
    struct pid_namespace *curr_ns = BPF_CORE_READ(current_task, nsproxy, pid_ns_for_children);
    struct pid_namespace *target_ns = BPF_CORE_READ(child, nsproxy, pid_ns_for_children);

    if (curr_ns != target_ns){
        bpf_printk("Blocking cause invalid namespace");
        return -1;
    }

    bpf_printk("Allowed as same cgid and pns");
    return 0;
}

char LICENSE[] SEC("license") = "GPL";