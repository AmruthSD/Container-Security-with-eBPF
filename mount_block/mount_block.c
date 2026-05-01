#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

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
    return val && *val;
}

static __always_inline int str_eq(const char *a, const char *b)
{
    char buf[16];

    bpf_core_read_str(buf, sizeof(buf), a);

#pragma unroll
    for (int i = 0; i < 16; i++)
    {
        if (buf[i] != b[i])
            return 0;
        if (buf[i] == '\0')
            break;
    }
    return 1;
}

SEC("lsm/security_sb_mount")
int BPF_PROG(restrict_mount,
             const char *dev_name,
             struct path *path,
             const char *type,
             unsigned long flags,
             void *data)
{

    if (!is_container())
        return 0;

    // -------------------------
    // 1. Block dangerous FS types
    // -------------------------
    if (type)
    {
        if (str_eq(type, "proc") ||
            str_eq(type, "sysfs") ||
            str_eq(type, "debugfs") ||
            str_eq(type, "tracefs") ||
            str_eq(type, "securityfs") ||
            str_eq(type, "cgroup") ||
            str_eq(type, "cgroup2"))
        {
            return -EPERM;
        }
    }

    // -------------------------
    // 2. Block device mounts
    // -------------------------
    if (dev_name)
    {
        char dev[32];
        bpf_core_read_str(dev, sizeof(dev), dev_name);

        // crude but effective: block /dev/*
        if (dev[0] == '/' && dev[1] == 'd' && dev[2] == 'e' && dev[3] == 'v')
        {
            return -EPERM;
        }
    }

    // -------------------------
    // 3. Block dangerous remounts
    // -------------------------
    if (flags & MS_REMOUNT)
    {
        if (flags & (MS_SUID | MS_DEV | MS_EXEC))
        {
            return -EPERM;
        }
    }

    // -------------------------
    // 4. Restrict tmpfs
    // -------------------------
    if (type && str_eq(type, "tmpfs"))
    {
        // enforce safe flags
        if (!(flags & MS_NOEXEC) ||
            !(flags & MS_NOSUID) ||
            !(flags & MS_NODEV))
        {
            return -EPERM;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";