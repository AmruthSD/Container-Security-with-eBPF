#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define MS_REMOUNT   32
#define MS_BIND      4096
#define MS_REC       16384

#define MS_NOSUID    2
#define MS_NODEV     4
#define MS_NOEXEC    8

#define MS_SUID      1
#define MS_DEV       2
#define MS_EXEC      4

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
    if(val && *val){
        bpf_printk("Container found with id %llu",cgid);
        return 1;
    }
    return 0;
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

SEC("lsm/sb_mount")
int BPF_PROG(restrict_mount,
             const char *dev_name,
             struct path *path,
             const char *type,
             unsigned long flags,
             void *data)
{
    if (!is_container())
        return 0;

    // 1. Block dangerous FS types
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
            bpf_printk("BLOCK: forbidden fs type\n");
            return -EPERM;
        }
    }

    // 2. Block device mounts
    if (dev_name)
    {
        char dev[32];
        bpf_core_read_str(dev, sizeof(dev), dev_name);

        if (dev[0] == '/' && dev[1] == 'd' && dev[2] == 'e' && dev[3] == 'v')
        {
            bpf_printk("BLOCK: device mount\n");
            return -EPERM;
        }
    }

    // 3. Block dangerous remounts
    if (flags & MS_REMOUNT)
    {
        bpf_printk("BLOCK: remount attempt\n");
        return -EPERM;
    }

    // 4. Restrict tmpfs
    if (type && str_eq(type, "tmpfs"))
    {
        if (!(flags & MS_NOEXEC) ||
            !(flags & MS_NOSUID) ||
            !(flags & MS_NODEV))
        {
            bpf_printk("BLOCK: unsafe tmpfs flags\n");
            return -EPERM;
        }
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";