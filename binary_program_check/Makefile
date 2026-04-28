CC=clang
CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ./

# Prefer pkg-config for portability
LIBBPF_CFLAGS=$(shell pkg-config --cflags libbpf 2>/dev/null)
LIBBPF_LIBS=$(shell pkg-config --libs libbpf 2>/dev/null)

# Fallback include path (Debian/Ubuntu)
LIBBPF_DIR=/usr/include/x86_64-linux-gnu

BPF_SRC=binary_checker.c
BPF_OBJ=binary_checker.o

LOADER=loader.py

.PHONY: all clean run debug mount-debugfs load unload

all: $(BPF_OBJ)

# Compile BPF program (LSM-compatible)
$(BPF_OBJ): $(BPF_SRC)
	$(CC) $(CFLAGS) $(LIBBPF_CFLAGS) -I $(LIBBPF_DIR) -c $< -o $@

# Run Python loader
run: $(BPF_OBJ)
	sudo python3 $(LOADER)

# Direct load using bpftool (LSM program type)
load: $(BPF_OBJ)
	sudo bpftool prog load $(BPF_OBJ) /sys/fs/bpf/file_opener type lsm

unload:
	sudo rm -f /sys/fs/bpf/file_opener

# Ensure debugfs is mounted
mount-debugfs:
	@mountpoint -q /sys/kernel/debug || sudo mount -t debugfs debugfs /sys/kernel/debug

# Live kernel debug output (bpf_printk)
debug: mount-debugfs
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(BPF_OBJ)