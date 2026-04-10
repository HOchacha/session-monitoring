This folder will contain generated Go bindings from bpf2go.

Planned command (example):

  go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -D__TARGET_ARCH_x86" Flow ../../bpf/flow.bpf.c -- -I../../bpf

Generated files are expected to be committed for reproducible builds.
