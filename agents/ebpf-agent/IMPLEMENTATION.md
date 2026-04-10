# eBPF Agent — 구현 상세

> Phase 0-3 완료 + VXLAN/VLAN/L3 디바이스 지원 (2026-04-08)

---

## 1. 아키텍처 개요

```
┌─────────────────────── Kernel ───────────────────────┐
│                                                       │
│   tc ingress (clsact qdisc)                           │
│   ┌─────────────┐                                     │
│   │ flow.bpf.c  │  L3/L2 자동 감지 → IPv4/IPv6 →       │
│   │ handle_     │  TCP/UDP 5-tuple · VXLAN · VLAN       │
│   │  ingress()  │                                     │
│   └──────┬──────┘                                     │
│          │ bpf_ringbuf_submit()                       │
│          ▼                                            │
│   ┌─────────────┐                                     │
│   │  ringbuf    │  16 MiB (BPF_MAP_TYPE_RINGBUF)      │
│   │  "events"   │                                     │
│   └──────┬──────┘                                     │
└──────────┼────────────────────────────────────────────┘
           │ epoll
┌──────────┼────────────── Userspace (Go) ─────────────┐
│          ▼                                            │
│   ┌─────────────┐    ┌──────────────┐                 │
│   │  consumer   │───▶│  FlowEvent   │                 │
│   │  (ringbuf   │    │  Go struct   │                 │
│   │   .Read())  │    │  (binary     │                 │
│   └─────────────┘    │   decode)    │                 │
│                      └──────┬───────┘                 │
│                             │ chan FlowEvent           │
│                             ▼                          │
│                      ┌──────────────┐                 │
│                      │   main.go    │                 │
│                      │   log output │                 │
│                      └──────────────┘                 │
└───────────────────────────────────────────────────────┘
```

**데이터 플로우:**
1. 패킷이 네트워크 인터페이스 ingress에 도착
2. tc/clsact qdisc의 BPF 필터가 `handle_ingress()` 호출
3. Ethernet/IP/TCP|UDP 헤더 파싱 후 `flow_event` 구조체 채움
   - L3 디바이스(tun): raw IP 패킷 → IP 헤더부터 직접 파싱
   - L2 디바이스(vnet/cloudbr): Ethernet → VLAN(선택) → IP 파싱
   - VXLAN(UDP:4789): inner Ethernet → inner IP → inner L4 재귀 파싱
4. `bpf_ringbuf_submit()`으로 userspace에 전달
5. Go의 `ringbuf.Reader`가 epoll로 이벤트 수신
6. `binary.Read()`로 `FlowEvent` Go 구조체로 디코딩
7. 메인 루프에서 로그 출력 (Phase 4에서 gRPC 전송 예정)

---

## 2. BPF 프로그램 (`bpf/flow.bpf.c`)

### 2.1 프로그램 타입

- **Section:** `SEC("tc")` — Traffic Control classifier
- **Attach point:** tc ingress (clsact qdisc)
- **반환값:** 항상 `BPF_OK` (패킷 통과, 관찰만 수행)

### 2.2 Map

```c
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); /* 16 MiB */
} events SEC(".maps");
```

- **ringbuf**: 단방향 커널→유저 이벤트 채널
- 16 MiB로 고부하에서도 드롭 최소화
- per-CPU가 아닌 공유 버퍼 (순서 보장)

### 2.3 파싱 흐름

```
skb 수신
 │
 ├── first_byte[7:4] + skb->protocol 교차 검증
 │    ├── IPv4(ver=4) + skb_proto=0x0800 → L3 디바이스 (ip_off=0)
 │    ├── IPv6(ver=6) + skb_proto=0x86DD → L3 디바이스 (ip_off=0)
 │    └── 그 외 → L2 (Ethernet) 경로
 │
 ├── [L2] offset 12: ethertype 읽기
 │    ├── 0x8100 (802.1Q) / 0x88A8 (QinQ)
 │    │    ├── TCI에서 12-bit VLAN ID 추출
 │    │    └── offset 16: 실제 ethertype → ip_off = ETH_HLEN + 4
 │    ├── 0x0800 (IPv4) → ip_off = ETH_HLEN
 │    ├── 0x86DD (IPv6) → ip_off = ETH_HLEN
 │    └── 기타 → 즉시 BPF_OK 반환
 │
 ├── ringbuf reserve (flow_event 크기)
 │
 ├── parse_l3(skb, ip_off, ...):
 │    ├── IPv4: ver_ihl → IHL 동적 계산, protocol, src/dst IP
 │    └── IPv6: next_header, src/dst IP (고정 40바이트)
 │
 ├── parse_l4(): src_port, dst_port (TCP/UDP)
 │
 ├── [VXLAN] UDP dst=4789 감지 시:
 │    ├── VXLAN I-flag 확인 → VNI 24-bit 추출
 │    ├── outer IP → outer_src_ip / outer_dst_ip 보존
 │    └── inner Ethernet → inner L3 → inner L4 재귀 파싱
 │
 └── ringbuf submit / discard
```

### 2.4 L4 파싱 (`parse_l4`)

```c
static __always_inline int parse_l4(struct __sk_buff *skb, __u32 off,
                                    __u8 proto, struct flow_event *e)
```

- TCP(6), UDP(17): src_port/dst_port 추출 (네트워크 바이트 오더 → 호스트)
- ICMP 등 기타 프로토콜: 포트 0으로 유지, 에러 없이 성공 반환
- L4 파싱 실패 시에도 L3 정보는 ringbuf에 전송 (데이터 손실 최소화)

### 2.5 Verifier 고려사항

- 모든 `bpf_skb_load_bytes()` 호출에 에러 체크
- 파싱 실패 시 `goto discard` → `bpf_ringbuf_discard()`로 메모리 누수 방지
- `__always_inline`으로 함수 호출 오버헤드 제거
- `__builtin_memset()`으로 구조체 초기화 (uninitialized memory 방지)

### 2.6 현재 제한사항

- IPv6 extension header 미추적 (next_header만 사용, 기본 헤더 40바이트 고정)
- QinQ (이중 VLAN 태그) — outer VLAN만 추출, inner VLAN 무시
- per-flow 집계 없음 — 모든 패킷을 개별 이벤트로 전송

---

## 3. 공유 구조체 (`bpf/common.h`)

```c
struct flow_event {
    __u64 ts_unix_nano;       // offset   0, size 8
    __u32 ifindex;            // offset   8, size 4
    __u8  ip_version;         // offset  12, size 1
    __u8  protocol;           // offset  13, size 1
    __u8  src_ip[16];         // offset  14, size 16
    __u8  dst_ip[16];         // offset  30, size 16
    __u16 src_port;           // offset  46, size 2
    __u16 dst_port;           // offset  48, size 2
    __u16 vlan_id;            // offset  50, size 2  (802.1Q; 0 = untagged)
    __u32 vni;                // offset  52, size 4  (VXLAN; 0 = non-VXLAN)
    __u8  outer_src_ip[16];   // offset  56, size 16 (tunnel endpoint)
    __u8  outer_dst_ip[16];   // offset  72, size 16
    __u64 bytes;              // offset  88, size 8
    __u64 packets;            // offset  96, size 8
};                            // total: 104 bytes
```

**주의: 패딩 정렬**
- `vlan_id`(2B) + `vni`(4B)가 기존 6바이트 패딩 공간을 대체
- `bytes` 필드가 8바이트 정렬(offset 88)을 만족
- Go 구조체에서 필드 순서를 정확히 대응

---

## 4. Go 코드 생성 (`internal/bpf/`)

### 4.1 bpf2go directive

```go
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go \
    -cc clang \
    -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" \
    -target bpfel \
    Flow ../../bpf/flow.bpf.c -- -I../../bpf
```

- `clang`으로 BPF C를 ELF로 컴파일
- `-O2 -g`: 최적화 + 디버그 정보 (BTF 생성에 필요)
- `-target bpfel`: little-endian BPF 타겟
- `-I../../bpf`: `common.h`, `vmlinux.h` 검색 경로

### 4.2 생성 결과물

| 파일 | 역할 |
|------|------|
| `flow_bpfel.o` | 컴파일된 BPF ELF (프로그램 + map 정의 + BTF) |
| `flow_bpfel.go` | Go 바인딩 (`FlowObjects`, `FlowMaps`, `FlowPrograms`) |

### 4.3 생성된 주요 타입

```go
type FlowObjects struct { FlowPrograms; FlowMaps; FlowVariables }
type FlowPrograms struct { HandleIngress *ebpf.Program }
type FlowMaps struct { Events *ebpf.Map }
```

---

## 5. BPF 로더 (`internal/collector/loader.go`)

### 5.1 `LoadAndAttach(ifaces []string) (*Attachments, error)`

전체 흐름:
1. `bpfgen.LoadFlowObjects()` — BPF ELF를 커널에 로드
2. 각 인터페이스에 `attachTC()` 호출
3. `ringbuf.NewReader(objs.Events)` — ringbuf 리더 생성

### 5.2 `attachTC()` — tc ingress 어태치

```
1. net.InterfaceByName() → ifindex 획득
2. netlink.LinkByIndex() → netlink 핸들
3. netlink.QdiscReplace() → clsact qdisc 생성 (idempotent)
4. netlink.FilterReplace() → BPF 필터 추가
   - Parent: HANDLE_MIN_INGRESS
   - Protocol: ETH_P_ALL
   - DirectAction: true
```

**clsact qdisc:**
- tc의 특수 qdisc로 ingress/egress 모두 지원
- 패킷 스케줄링 없이 classifier만 실행
- `QdiscReplace`로 이미 존재해도 에러 없음

**BPF filter 옵션:**
- `DirectAction: true` — BPF 프로그램 반환값을 tc action으로 직접 사용
- `Priority: 1` — 필터 우선순위
- `Protocol: ETH_P_ALL` — 모든 프로토콜 매칭

### 5.3 `Close()` — 정리

1. ringbuf reader 닫기
2. 모든 tc 필터 제거 (`netlink.FilterDel`)
3. BPF 오브젝트 해제 (`Objects.Close`)

어태치 실패한 인터페이스는 WARN 로그만 남기고 건너뛰므로, 일부 실패해도 나머지는 동작한다.

---

## 6. Ringbuf 컨슈머 (`internal/collector/consumer.go`)

### 6.1 `ConsumeEvents(ctx, rd) <-chan FlowEvent`

- gorouting에서 `rd.Read()` 블로킹 루프
- 수신된 raw 바이트를 `decodeFlowEvent()`로 디코딩
- 256 버퍼 채널로 전달 (백프레셔 역할)
- `ctx.Done()` 또는 `ringbuf.ErrClosed`로 종료

### 6.2 디코딩

```go
func decodeFlowEvent(raw []byte) (events.FlowEvent, error) {
    binary.Read(bytes.NewReader(raw), binary.LittleEndian, &ev)
}
```

- `binary.LittleEndian`: x86 BPF 타겟과 일치
- Go `FlowEvent` 구조체의 필드 순서/크기/패딩이 C 구조체와 정확히 매칭

### 6.3 `FormatIP(ip [16]byte, version uint8) string`

- IPv4: 앞 4바이트만 사용 → `net.IP(ip[:4]).String()`
- IPv6: 16바이트 전체 → `net.IP(ip[:]).String()`

---

## 7. FlowEvent Go 구조체 (`internal/events/types.go`)

```go
type FlowEvent struct {
    TSUnixNano uint64      // 8B
    IfIndex    uint32      // 4B
    IPVersion  uint8       // 1B
    Protocol   uint8       // 1B
    SrcIP      [16]byte    // 16B
    DstIP      [16]byte    // 16B
    SrcPort    uint16      // 2B
    DstPort    uint16      // 2B
    VlanID     uint16      // 2B  (802.1Q VLAN ID; 0 = untagged)
    VNI        uint32      // 4B  (VXLAN Network Identifier; 0 = non-VXLAN)
    OuterSrcIP [16]byte    // 16B (tunnel endpoint src)
    OuterDstIP [16]byte    // 16B (tunnel endpoint dst)
    Bytes      uint64      // 8B
    Packets    uint64      // 8B
}                          // Total: 104B
```

`VlanID`(2B)와 `VNI`(4B)가 이전 6바이트 패딩 공간을 대체하여 구조체 크기가 동일(104B)하게 유지된다.

---

## 8. 인터페이스 탐색 (`internal/collector/interfaces.go`)

### 8.1 `DiscoverAttachInterfaces(sel InterfaceSelector) ([]string, error)`

1. `net.Interfaces()`로 시스템 전체 인터페이스 목록 획득
2. `require_up: true`면 UP 플래그 없는 인터페이스 제외
3. `exclude_prefixes` 매칭 → 제외
4. `include_prefixes` 매칭 → 포함
5. 이름 기준 정렬 후 반환

### 8.2 프리픽스 매칭

- 대소문자 무관 (소문자 정규화 후 비교)
- 빈 문자열/공백 자동 무시
- 탐색 결과 0개면 `main.go`에서 `log.Fatalf` (fail-fast)

---

## 9. 설정 시스템 (`cmd/ebpf-agent/config.go`)

### 9.1 설정 파일 탐색

```
1. EBPF_AGENT_CONFIG_PATH 환경변수
2. configs/agents/ebpf-agent.yaml (상대)
3. ../../configs/agents/ebpf-agent.yaml
4. /etc/openvpn-monitoring/ebpf-agent.yaml
```

### 9.2 기본값

```yaml
agent:
  name: ebpf-agent
interfaces:
  include_prefixes: [vnet, cloudbr, brvx, tun, vxlan]
  exclude_prefixes: [lo, docker, veth, virbr, cni, flannel, kube]
  require_up: true
```

설정 파일에 필드가 없으면 Go 코드에서 기본값을 채운다. `include_prefixes`가 비어있으면 validation 에러.

---

## 10. 메인 파이프라인 (`cmd/ebpf-agent/main.go`)

```
signal.NotifyContext(SIGINT, SIGTERM)
        │
        ▼
resolveConfigPath() → loadConfig() → validate()
        │
        ▼
cfg.toSelector() → DiscoverAttachInterfaces()
        │
        ▼
rlimit.RemoveMemlock()  // 커널 < 5.11 호환
        │
        ▼
LoadAndAttach(ifaces)
   ├── BPF ELF 로드
   ├── clsact qdisc 생성
   ├── tc ingress 필터 어태치
   └── ringbuf reader 생성
        │
        ▼
ConsumeEvents(ctx, reader)  // goroutine 시작
        │
        ▼
main select loop
   ├── <-events:  flow 로그 출력
   └── <-ctx.Done():
        ├── reader.Close()  // ringbuf 해제
        ├── drain channel   // 잔여 이벤트 소비
        └── att.Close()     // tc 필터 제거 + BPF 해제
```

### 정상 종료 시퀀스

1. `Ctrl+C` → context 취소
2. `att.Reader.Close()` → consumer goroutine이 `ErrClosed` 받고 채널 닫음
3. 잔여 이벤트 drain
4. `defer att.Close()` → tc 필터 제거, BPF 오브젝트 해제

---

## 11. 의존성

| 패키지 | 버전 | 용도 |
|--------|------|------|
| `github.com/cilium/ebpf` | v0.21.0 | BPF 로드, ringbuf 리더 |
| `github.com/vishvananda/netlink` | v1.3.1 | tc qdisc/filter 관리 |
| `golang.org/x/sys` | v0.37.0 | unix 상수 (ETH_P_ALL 등) |
| `gopkg.in/yaml.v3` | v3.0.1 | 설정 파일 파싱 |

빌드 도구:
- `clang 18` — BPF C 컴파일 (CO-RE, BTF)
- `bpf2go` (cilium/ebpf/cmd/bpf2go) — `go generate`로 Go 바인딩 생성

---

## 12. 테스트

### 단위 테스트

| 파일 | 테스트 항목 |
|------|-------------|
| `cmd/ebpf-agent/config_test.go` | 환경변수 오버라이드, 기본값 적용 |
| `internal/collector/interfaces_test.go` | 프리픽스 정규화, hasPrefix 매칭 |
| `internal/collector/consumer_test.go` | IPv4/IPv6/VXLAN/VLAN decode, FormatIP, 잘린 데이터 에러 |

```bash
$ go test ./... -v
=== RUN   TestResolveConfigPath_UsesEnvOverride        PASS
=== RUN   TestLoadConfig_AppliesDefaults               PASS
=== RUN   TestDecodeFlowEvent_IPv4TCP                  PASS
=== RUN   TestDecodeFlowEvent_IPv6UDP                  PASS
=== RUN   TestDecodeFlowEvent_VXLAN                    PASS
=== RUN   TestDecodeFlowEvent_VLAN                     PASS
=== RUN   TestDecodeFlowEvent_TruncatedData            PASS
=== RUN   TestFormatIP_v4                              PASS
=== RUN   TestFormatIP_v6                              PASS
=== RUN   TestNormalizePrefixes                        PASS
=== RUN   TestHasPrefix                                PASS
PASS
```

### 실 환경 검증

```bash
$ sudo ./ebpf-agent
2026/03/17 06:41:09 ebpf-agent starting (config=../../configs/agents/ebpf-agent.yaml)
2026/03/17 06:41:09 attach candidates: [tun0]
2026/03/17 06:41:09 attached tc/ingress on tun0
2026/03/17 06:41:09 ringbuf consumer starting

$ sudo tc filter show dev tun0 ingress
filter protocol all pref 1 bpf chain 0
filter protocol all pref 1 bpf chain 0 handle 0x1 ebpf-agent/ingress \
    direct-action not_in_hw id 279 name handle_ingress tag ae03008a36ee1d28 jited

$ sudo bpftool prog list | grep handle_ingress
279: sched_cls  name handle_ingress  tag ae03008a36ee1d28  gpl
        loaded_at 2026-03-17T06:44:41+0000  uid 0
        xlated 1120B  jited 703B  memlock 4096B  map_ids 22
```

- BPF 프로그램: 1120B xlated, 703B JIT 컴파일
- 정상 종료 시 tc 필터 자동 제거 확인

---

## 13. 설계 결정 & 트레이드오프

| 결정 | 이유 |
|------|------|
| tc ingress (clsact) vs XDP | tc는 L2 헤더 접근 가능, 가상 인터페이스(vnet) 지원, XDP는 물리 NIC만 |
| ringbuf vs perf_event_array | ringbuf: 공유 버퍼로 순서 보장, 메모리 효율적, 커널 5.8+ |
| per-packet emit vs per-flow aggregation | MVP에서는 단순성 우선, Phase 4에서 배칭으로 보완 |
| CO-RE (vmlinux.h) vs libbpf-bootstrap | cilium/ebpf의 bpf2go가 Go 생태계에 자연스러움 |
| fail-soft (skip interface) vs fail-fast | 일부 인터페이스 어태치 실패해도 나머지 동작 (운영 안정성) |
| BPF_OK 반환 (passthrough) | 관찰 전용 — 패킷 드롭/수정 없음 |
| L3/L2 자동 감지 | `first_byte[7:4]` + `skb->protocol` 교차 검증으로 tun(raw IP)과 Ethernet 디바이스 모두 지원 |
| VLAN ID in flow_event | 기존 패딩 공간(2B)을 활용, 구조체 크기 변경 없이 추가 |
