#include <errno.h>
#include <linux/bpf.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <iostream>

static int bpf_syscall(enum bpf_cmd cmd, union bpf_attr *attr)
{
    return syscall(__NR_bpf, cmd, attr, sizeof(*attr));
}

int main()
{
    sleep(5); // allow the loader and control plane to attach/track the container

    union bpf_attr attr;
    memset(&attr, 0, sizeof(attr));

    attr.map_type = BPF_MAP_TYPE_ARRAY;
    attr.key_size = sizeof(int);
    attr.value_size = sizeof(int);
    attr.max_entries = 1;

    int fd = bpf_syscall(BPF_MAP_CREATE, &attr);
    if (fd < 0) {
        std::cout << "[BLOCKED] bpf(BPF_MAP_CREATE) failed (errno="
                  << errno << " " << strerror(errno) << ")\n";
        return 1;
    }

    std::cout << "[ALLOWED] bpf(BPF_MAP_CREATE) succeeded, fd=" << fd << "\n";
    close(fd);
    return 0;
}
