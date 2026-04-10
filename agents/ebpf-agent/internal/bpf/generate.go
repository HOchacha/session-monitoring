package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" -target bpfel Flow ../../bpf/flow.bpf.c -- -I../../bpf
