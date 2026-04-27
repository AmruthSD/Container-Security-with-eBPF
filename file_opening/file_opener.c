#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 64
#define PREFIX_LEN 128

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
#pragma unroll
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
    struct inode *inode = file->f_inode;

    // ---------- FAST PATH: inode ----------
    struct inode_key key = {
        .ino = inode->i_ino,
        .dev = inode->i_sb->s_dev,
    };

    u8 *blocked = bpf_map_lookup_elem(&inode_blacklist, &key);
    if (blocked)
    {
        bpf_printk("BLOCK (inode): dev=%llu ino=%llu\n", key.dev, key.ino);
        return -1;
    }

    // ---------- FALLBACK: path ----------
    char path[256];
    int ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0)
        return 0;

#pragma unroll
    for (int i = 0; i < MAX_ENTRIES; i++)
    {
        u32 k = i;
        struct prefix *p = bpf_map_lookup_elem(&prefix_blacklist, &k);
        if (!p)
            continue;

        if (has_prefix(path, p->path))
        {
            bpf_printk("BLOCK (prefix): %s\n", path);
            return -1;
        }
    }

    return 0;
}