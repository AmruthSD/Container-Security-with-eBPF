#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 8
#define PREFIX_LEN 128

// --------------------
// Cgroup filter map
// --------------------
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // cgroup id
    __type(value, __u8);
} cgroup_filter SEC(".maps");

// --------------------
// Inode-based map
// --------------------
struct inode_key
{
    u64 dev;
    u64 ino;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, struct inode_key);
    __type(value, u8);
} inode_blacklist SEC(".maps");

// --------------------
// Prefix-based map
// --------------------
struct prefix
{
    char path[PREFIX_LEN];
};

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, u32);
    __type(value, struct prefix);
} prefix_blacklist SEC(".maps");

// --------------------
// Prefix match helper
// --------------------
static __always_inline int has_prefix(char *path, char *prefix)
{
    for (int i = 0; i < PREFIX_LEN; i++)
    {
        if (prefix[i] == '\0')
            return 1;
        if (path[i] != prefix[i])
            return 0;
    }
    return 0;
}

// --------------------
// LSM Hook
// --------------------
SEC("lsm/file_open")
int BPF_PROG(block_file, struct file *file)
{
    // ---------- CGROUP CHECK ----------
    u64 cgid = bpf_get_current_cgroup_id();
    u8 *is_filtered = bpf_map_lookup_elem(&cgroup_filter, &cgid);

    // Only proceed with blocking logic if the current cgroup is in the map
    if (!is_filtered)
    {
        return 0;
    }

    bpf_printk("Found a container with cgid=%llu",cgid);

    struct inode *inode = file->f_inode;

    // ---------- FAST PATH: inode ----------
    struct inode_key key = {
        .ino = inode->i_ino,
        .dev = inode->i_sb->s_dev,
    };

    u8 *blocked = bpf_map_lookup_elem(&inode_blacklist, &key);
    if (blocked)
    {
        bpf_printk("BLOCK (inode): cgroup=%llu dev=%llu ino=%llu\n", cgid, key.dev, key.ino);
        return -1; // EPERM
    }

    // ---------- FALLBACK: path ----------
    char path[256];
    int ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0)
        return 0;

    for (int i = 0; i < MAX_ENTRIES; i++)
{
    u32 k = i;
    struct prefix *p = bpf_map_lookup_elem(&prefix_blacklist, &k);
    if (!p)
        continue;

    if (p->path[0] == '\0')
        continue;

    if (has_prefix(path, p->path))
    {
        char prefix_buf[64];
        __builtin_memcpy(prefix_buf, p->path, sizeof(prefix_buf));

        bpf_printk("BLOCK prefix: cgid=%llu prefix=%s\n", cgid, prefix_buf);
        bpf_printk("BLOCK (prefix): cgroup=%llu %s\n", cgid, path);

        return -1; // EPERM
    }
}

    return 0;
}