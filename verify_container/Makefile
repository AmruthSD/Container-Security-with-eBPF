CC=clang
CFLAGS=-O2 -g -Wall -target bpf
LIBBPF_DIR=/usr/include/x86_64-linux-gnu

BPF_OBJ=check_std_write.o
LOADER=loader.py

.PHONY: all clean run debug mount-debugfs

all: $(BPF_OBJ)

$(BPF_OBJ): check_std_write.c
	$(CC) $(CFLAGS) -I $(LIBBPF_DIR) -c $< -o $@

# Compile + run loader
run: $(BPF_OBJ)
	sudo python3 $(LOADER)

# Ensure debugfs is mounted
mount-debugfs:
	@mountpoint -q /sys/kernel/debug || sudo mount -t debugfs debugfs /sys/kernel/debug

# Live kernel debug output (bpf_printk, etc.)
debug: mount-debugfs
	sudo cat /sys/kernel/debug/tracing/trace_pipe

clean:
	rm -f $(BPF_OBJ)