# Session Monitoring — Build System
#
# 처음 클론 후 전체 빌드:
#   make deps       # clang-18, llvm-18, bpftool 설치 (sudo 필요)
#   make vmlinux    # 실행 중인 커널 BTF에서 vmlinux.h 생성
#   make generate   # flow.bpf.c 컴파일 → Go 바인딩 자동 생성
#   make build      # 전체 바이너리 빌드
#
# 또는 한 번에:
#   make setup      # deps + vmlinux + generate + build

EBPF_DIR       := agents/ebpf-agent
OPENVPN_DIR    := agents/openvpn-exporter
VMLINUX_H      := $(EBPF_DIR)/bpf/vmlinux.h
KERNEL_RELEASE := $(shell uname -r)

# 기본 타겟 — vmlinux.h와 generate가 이미 완료된 상태에서의 일반 빌드
.DEFAULT_GOAL := build

.PHONY: all setup deps vmlinux generate \
        build build-ebpf build-openvpn \
        test test-ebpf test-openvpn \
        clean clean-all help

# ── 편의 타겟 ──────────────────────────────────────────────────────────

all: vmlinux generate build  ## vmlinux 재생성 + BPF 재컴파일 + 전체 빌드

setup: deps vmlinux generate build  ## 첫 클론 후 전체 환경 구성 및 빌드

# ── 의존성 설치 ────────────────────────────────────────────────────────

deps:  ## clang-18, llvm-18, bpftool 설치 (sudo 권한 필요)
	@echo "→ apt 패키지 설치 중 (clang-18, llvm-18, bpftool)..."
	sudo apt-get update -qq
	sudo apt-get install -y clang-18 llvm-18 libbpf-dev \
	    linux-tools-$(KERNEL_RELEASE) linux-tools-common 2>/dev/null \
	    || sudo apt-get install -y clang-18 llvm-18 libbpf-dev linux-tools-common
	@echo "→ clang / llvm-strip 심볼릭 링크 생성..."
	@if ! command -v clang >/dev/null 2>&1; then \
	    sudo ln -sf /usr/bin/clang-18 /usr/local/bin/clang; \
	    echo "   clang -> /usr/bin/clang-18"; \
	fi
	@if ! command -v llvm-strip >/dev/null 2>&1; then \
	    sudo ln -sf /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip; \
	    echo "   llvm-strip -> /usr/bin/llvm-strip-18"; \
	fi
	@echo "→ 의존성 설치 완료"

# ── vmlinux.h 생성 ─────────────────────────────────────────────────────

vmlinux: $(VMLINUX_H)  ## 실행 중인 커널 BTF로 vmlinux.h 생성

$(VMLINUX_H):
	@echo "→ vmlinux.h 생성 중 (kernel $(KERNEL_RELEASE))..."
	@if [ ! -f /sys/kernel/btf/vmlinux ]; then \
	    echo "오류: /sys/kernel/btf/vmlinux 없음 — CONFIG_DEBUG_INFO_BTF=y 필요"; \
	    exit 1; \
	fi
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "→ $(VMLINUX_H) 생성 완료 ($$(wc -l < $(VMLINUX_H)) 줄)"

# ── BPF 코드 생성 (bpf2go) ─────────────────────────────────────────────

generate: $(VMLINUX_H)  ## flow.bpf.c 컴파일 → flow_bpfel.go / flow_bpfel.o 재생성
	@echo "→ bpf2go 실행 중..."
	@command -v clang >/dev/null 2>&1 || \
	    { echo "오류: clang 없음 — 'make deps' 먼저 실행"; exit 1; }
	cd $(EBPF_DIR) && go generate ./internal/bpf/
	@echo "→ BPF 바인딩 생성 완료"

# ── Go 빌드 ───────────────────────────────────────────────────────────

build: build-ebpf build-openvpn  ## 전체 에이전트 바이너리 빌드

build-ebpf:  ## ebpf-agent 바이너리 빌드 → agents/ebpf-agent/ebpf-agent
	@echo "→ ebpf-agent 빌드 중..."
	cd $(EBPF_DIR) && go build -o ebpf-agent ./cmd/ebpf-agent/

build-openvpn:  ## openvpn-session-agent 바이너리 빌드
	@echo "→ openvpn-session-agent 빌드 중..."
	cd $(OPENVPN_DIR) && mkdir -p bin && go build -o bin/openvpn-session-agent ./cmd/session-agent/

# ── 테스트 ────────────────────────────────────────────────────────────

test: test-ebpf test-openvpn  ## 전체 유닛 테스트 실행

test-ebpf:  ## ebpf-agent 유닛 테스트
	cd $(EBPF_DIR) && go test -v ./...

test-openvpn:  ## openvpn-exporter 유닛 테스트
	cd $(OPENVPN_DIR) && go test -v ./...

# ── 정리 ─────────────────────────────────────────────────────────────

clean:  ## 빌드된 바이너리만 삭제 (생성된 .go/.o 파일 유지)
	rm -f $(EBPF_DIR)/ebpf-agent
	rm -f $(OPENVPN_DIR)/bin/openvpn-session-agent

clean-all: clean  ## 바이너리 + bpf2go 생성물 + vmlinux.h 전체 삭제
	rm -f $(VMLINUX_H)
	rm -f $(EBPF_DIR)/internal/bpf/flow_bpfel.go
	rm -f $(EBPF_DIR)/internal/bpf/flow_bpfel.o

# ── 도움말 ───────────────────────────────────────────────────────────

help:  ## 사용 가능한 타겟 목록 출력
	@echo "사용법: make [타겟]"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) \
	    | awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'
	@echo ""
	@echo "첫 클론 후 전체 설정:"
	@echo "  make setup"
