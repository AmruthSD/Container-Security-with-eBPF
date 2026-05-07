BPF_CLANG=clang
CFLAGS=-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ../ptrace_block

BPF_SRC=kill_block.c
BPF_OBJ=kill_block.o
LOADER=loader.py

.PHONY: all clean run

all: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC)
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

run: $(BPF_OBJ)
	sudo python3 $(LOADER)

clean:
	rm -f $(BPF_OBJ)
