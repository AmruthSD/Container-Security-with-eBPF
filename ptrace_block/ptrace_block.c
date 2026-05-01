#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>
#include "vmlinux.h"

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

    __u64 target_cgid = bpf_task_get_cgroup_id(child, 0);

    if (current_cgid != target_cgid)
        return -1;

    // PID namespace check
    struct pid_namespace *curr_ns = current_task->nsproxy->pid_ns_for_children;
    struct pid_namespace *target_ns = child->nsproxy->pid_ns_for_children;

    if (curr_ns != target_ns)
        return -1;

    return 0;
}