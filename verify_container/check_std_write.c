#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>

#define MAX_BUF 80

#define HOST_CGROUP_ID 10007

struct trace_event_raw_sys_enter {
    long unused;
    long syscall_nr;
    long args[6];
};

SEC("tracepoint/syscalls/sys_enter_write")
int trace_write_stdout(struct trace_event_raw_sys_enter *ctx)
{
    int fd = (int)ctx->args[0];
    const char *user_buf = (const char *)ctx->args[1];
    __u64 count = (__u64)ctx->args[2];

    /* Only stdout */
    if (fd != 1)
        return 0;

    /* Check container */
    __u64 cg_id = bpf_get_current_cgroup_id();
    if (cg_id == HOST_CGROUP_ID)
        return 0;   /* host process → ignore */

    char buf[MAX_BUF];
    __u64 to_copy = count < (MAX_BUF - 1) ? count : (MAX_BUF - 1);

    if (bpf_probe_read_user(buf, to_copy, user_buf) < 0)
        return 0;

    buf[to_copy] = '\0';

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    bpf_printk(
        "CONTAINER stdout | pid=%d | cgroup=%llu | \"%s\"\n",
        pid, cg_id, buf
    );

    return 0;
}

char LICENSE[] SEC("license") = "GPL";