# Container Security with eBPF

Small eBPF/LSM experiments for applying security policies to Docker containers.

The common idea is:

1. A userspace control plane watches Docker containers.
2. It resolves each container's cgroup id.
3. It stores tracked cgroup ids in a pinned BPF map at `/sys/fs/bpf/cgroup_filter`.
4. Each eBPF program checks the current process cgroup id before enforcing a policy.

## Repository Layout

| Directory | Hook | Purpose |
| --- | --- | --- |
| `file_opening` | `lsm/file_open` | Blocks protected files or path prefixes inside tracked containers |
| `mount_block` | `lsm/sb_mount` | Blocks dangerous mounts such as `proc`, `sysfs`, `debugfs`, device mounts, remounts, and unsafe `tmpfs` |
| `ptrace_block` | `lsm/ptrace_access_check` | Blocks ptrace across cgroups or PID namespaces |
| `kill_block` | `lsm/task_kill` | Blocks signals across cgroups or PID namespaces |
| `setuid_block` | `lsm/task_fix_setuid` | Blocks `setuid()` inside tracked containers |
| `capset_block` | `lsm/capset` | Blocks capability changes inside tracked containers |
| `bpf_block` | `lsm/bpf` | Blocks the `bpf(2)` syscall inside tracked containers |
| `binary_program_check` | `lsm/bprm_check_security` | Learns known executables for a container, then blocks unknown binaries |

## How It Works

```c
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u64);
    __type(value, __u8);
} cgroup_filter SEC(".maps");
```

At runtime the program calls:

```c
__u64 cgid = bpf_get_current_cgroup_id();
__u8 *enabled = bpf_map_lookup_elem(&cgroup_filter, &cgid);
```

If the cgroup id is present, the policy is enforced. Returning `0` allows the operation. Returning `-EPERM` or `-1` blocks it.

The Python loaders open the compiled `.o` file, bind `cgroup_filter` to the pinned map path, load the program, attach it to the LSM hook, and stay alive while the link is attached.

## Basic Usage

Start the container control plane first:

```bash
sudo python3 detect_container/control_plane.py
```

In another terminal, build and attach one policy:

```bash
cd mount_block
make
sudo python3 loader.py
```

In a third terminal, run that demo's container:

```bash
./run_continer.sh
```