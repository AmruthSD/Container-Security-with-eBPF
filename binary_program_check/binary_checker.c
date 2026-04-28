#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

#define STATE_LEARNING 0
#define STATE_STABLE 1
#define STATE_ENFORCING 2

#define LEARN_WINDOW_NS (30ULL * 1000000000) // 30s
#define GRACE_WINDOW_NS (30ULL * 1000000000) // 30s

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // cgroup id
    __type(value, __u8);
} cgroup_filter SEC(".maps");

struct cg_state
{
    __u8 state;
    __u64 last_new_exec_ns;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64); // cgroup id
    __type(value, struct cg_state);
} cg_state_map SEC(".maps");

struct file_id
{
    __u64 dev;
    __u64 ino;
};

struct exec_key
{
    __u64 cgid;
    struct file_id fid;
};

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, struct exec_key);
    __type(value, __u8);
} allow_map SEC(".maps");

SEC("lsm/bprm_check_security")
int BPF_PROG(exec_control, struct linux_binprm *bprm)
{
    __u64 cgid = bpf_get_current_cgroup_id();


    // check if this cgroup is monitored
    __u8 *enabled = bpf_map_lookup_elem(&cgroup_filter, &cgid);
    if (!enabled)
        return 0;

    bpf_printk("Found a container");
    char filename[256];
    bpf_probe_read_str(filename, sizeof(filename), bprm->filename);

    bpf_printk("cgid=%llu exec file=%s\n", cgid, filename);

    // get file + inode
    struct file *file = bprm->file;
    if (!file)
        return 0;

    struct inode *inode = file->f_inode;
    if (!inode)
        return 0;

    struct exec_key key = {};
    key.cgid = cgid;
    key.fid.ino = inode->i_ino;
    key.fid.dev = inode->i_sb->s_dev;

    __u64 now = bpf_ktime_get_ns();

    // lookup state
    struct cg_state *st = bpf_map_lookup_elem(&cg_state_map, &cgid);

    if (!st)
    {
        // initialize state
        struct cg_state new_state = {};
        new_state.state = STATE_LEARNING;
        new_state.last_new_exec_ns = now;

        bpf_map_update_elem(&cg_state_map, &cgid, &new_state, BPF_ANY);
        return 0;
    }

    // check if this exec is already known
    __u8 *allowed = bpf_map_lookup_elem(&allow_map, &key);

    if (!allowed)
    {
        // new binary observed → learn it
        __u8 one = 1;
        bpf_map_update_elem(&allow_map, &key, &one, BPF_ANY);

        st->last_new_exec_ns = now;
    }

    // compute time since last new exec
    __u64 delta = now - st->last_new_exec_ns;

    // state transitions (simple version)
    if (delta < LEARN_WINDOW_NS)
    {
        st->state = STATE_LEARNING;
    }
    else if (delta < (LEARN_WINDOW_NS + GRACE_WINDOW_NS))
    {
        st->state = STATE_STABLE;
    }
    else
    {
        st->state = STATE_ENFORCING;
    }

    // enforcement
    if (st->state == STATE_ENFORCING)
    {
        if (!allowed)
        {
            return -1; // deny
        }
    }

    return 0;
}