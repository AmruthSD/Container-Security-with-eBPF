BPF_CLANG=clang
CFLAGS=-O2 -g -target bpf

all: capset_block.o

capset_block.o: capset_block.c
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o test_capset
