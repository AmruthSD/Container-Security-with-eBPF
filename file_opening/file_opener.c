#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_ENTRIES 64

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

SEC("lsm/file_open")
int BPF_PROG(block_file, struct file *file)
{
    struct inode *inode = file->f_inode;

    struct inode_key key = {
        .ino = inode->i_ino,
        .dev = inode->i_sb->s_dev};

    u8 *blocked = bpf_map_lookup_elem(&inode_blacklist, &key);

    if (blocked)
    {
        bpf_printk("Blocked inode: dev=%llu ino=%llu\n", key.dev, key.ino);
        return -1;
    }

    return 0;
}