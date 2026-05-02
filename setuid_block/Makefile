BPF_CLANG=clang
CFLAGS=-O2 -g -target bpf

all: setuid_block.o

setuid_block.o: setuid_block.c
	$(BPF_CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o test_setuid
