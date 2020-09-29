tohex:
	$(shell sh tohex.sh)

elf:
	clang -I. -O2 -target bpf -c icmp.c  -o icmp.elf

all: elf tohex
