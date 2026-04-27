#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/file_open")
int BPF_PROG(block_file, struct file *file)
{
    char path[128];

    // Get full resolved path
    int ret = bpf_d_path(&file->f_path, path, sizeof(path));
    if (ret < 0)
        return 0;

    char target[] = "/home/amruth/Desktop/mini_project/Container-Security-with-eBPF/file_opening/protected.txt";

// Compare character-by-character (verifier-safe)
#pragma unroll
    for (int i = 0; i < sizeof(target); i++)
    {
        if (target[i] == '\0')
            break;

        if (path[i] != target[i])
            return 0; // not a match
    }

    // Ensure exact match (avoid "/etc/shadow123")
    if (path[sizeof(target) - 1] == '\0')
    {
        bpf_printk("Blocked access to /etc/shadow\n");
        return -1; // deny
    }

    return 0; // allow
}