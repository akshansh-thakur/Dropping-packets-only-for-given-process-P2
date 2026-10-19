
CLANG ?= clang
CC ?= gcc

all: filter.bpf.o loader

filter.bpf.o: filter.bpf.c
	$(CLANG) -O2 -g -target bpf -c $< -o $@

loader: loader.c
	$(CC) -O2 -Wall $< -o $@ -lbpf -lelf -lz

clean:
	rm -f filter.bpf.o loader
