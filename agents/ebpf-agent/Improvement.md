# eBPF Agent — 성능 개선 기록

> 적용일: 2026-04-20

---

## 문제 요약

TC-BPF를 **단일 병목 인터페이스(tun0)**에 부착하면 모든 VPN 클라이언트 트래픽이 하나의 BPF hook을 통과한다. 이 구조에서 성능 저하를 유발하는 요인이 세 가지 겹쳐 있었다.

| # | 문제 | 영향 |
|---|------|------|
| 1 | **Dead code**: tun은 L3 디바이스인데 L2/VLAN/VXLAN 파싱 경로가 전부 존재 | 불필요한 분기 + verifier 검증 비용 |
| 2 | **`bpf_skb_load_bytes()` 과다 호출**: 패킷당 6~8회. 이 helper는 non-linear skb를 위한 범용 함수라 오버헤드가 큼 | 패킷당 불필요한 helper call 비용 |
| 3 | **Ringbuf per-packet 모델**: 패킷마다 ringbuf에 event를 write → userspace가 epoll로 즉시 소비. 패킷 수에 비례해 IPC 오버헤드 선형 증가 | 고트래픽 시 userspace CPU 폭주 |

---

## 적용된 개선사항

### 1. BPF 프로그램 경량화 — tun 전용 재작성 (`bpf/flow.bpf.c`)

**변경 전**: L3/L2 자동 감지 → VLAN 파싱 → VXLAN inner/outer 파싱 (247줄)

**변경 후**: IPv4/IPv6 직접 파싱만 남김 (80줄)

- 제거: Ethernet 헤더 파싱, 802.1Q/802.1ad VLAN 처리, VXLAN(UDP:4789) inner 파싱
- tun은 raw IP 패킷만 전달하므로 이 코드들은 실행되지 않는 dead code였음
- BPF instruction count 대폭 감소 → JIT 캐시 효율 향상, verifier 시간 단축

### 2. Direct packet access 전환 (`bpf/flow.bpf.c`)

**변경 전**: `bpf_skb_load_bytes(skb, offset, buf, len)` — 패킷 데이터를 로컬 버퍼에 복사하는 helper

**변경 후**: `void *data = (void *)(long)skb->data` 직접 포인터 접근

```c
// 이전: helper call (범용, non-linear skb 대응)
bpf_skb_load_bytes(skb, ip_off + 9, &proto, 1);

// 이후: direct access (bounds check만 추가)
key.protocol = *((__u8 *)data + 9);
```

- tun 패킷은 항상 linear → direct access 완전히 안전
- `DirectAction: true`로 어태치되어 있어 direct access 사용 가능 (kernel 4.7+)
- helper call overhead 제거: helper 디스패치 비용 + 내부 복사 비용 절감

### 3. Ringbuf → PERCPU_HASH + 주기적 drain 모델 (`bpf/flow.bpf.c`, `consumer.go`)

**변경 전**: 패킷마다 `bpf_ringbuf_submit()` → userspace epoll 소비 → binary.Unmarshal

**변경 후**: 패킷마다 map의 카운터만 증분 → userspace가 5초마다 map 전체를 drain

```
[BPF hot path]           [Userspace, 5s interval]
패킷 도착                 ticker
  ↓                        ↓
map lookup + +=           map.Iterate()
  (per-CPU, lock-free)    per-CPU sum
  ↓                       emit FlowEvent
BPF_OK (즉시 반환)        map.Delete()
```

- **per-CPU map**: CPU당 독립 카운터 → lock/atomic 완전 없음
- **패킷당 BPF 작업**: lookup + 증분만 (ringbuf write 없음)
- **userspace IPC 비용**: N패킷당 1회 (이전: N패킷당 N회 epoll 깨우기)

### 4. 구조체 슬림화 (`bpf/common.h`, `events/types.go`)

| 구조체 | 변경 전 | 변경 후 | 제거된 필드 |
|--------|---------|---------|------------|
| `flow_key` | 48 bytes | 44 bytes | `vlan_id`, `vni` |
| `flow_metrics` | 64 bytes | 32 bytes | `outer_src_ip`, `outer_dst_ip` |

- PERCPU_HASH 엔트리 하나가 `CPU수 × sizeof(flow_metrics)` 크기를 점유
- flow_metrics가 64→32 bytes: 16-CPU 호스트 기준 엔트리당 512B 절감

### 5. 인터페이스 기본값 변경 (`interfaces.go`, `config.go`)

**변경 전**: `include_prefixes: [vnet, cloudbr, brvx, tun, vxlan]` — bridge/overlay 포함

**변경 후**: `include_prefixes: [tun]` — tun 전용

bridge/overlay 인터페이스(`brvx*`, `vxlan*`, `cloudbr*`)를 제거해 동일 트래픽의 중복 처리를 방지한다. 이 인터페이스들은 `vnet*` 또는 `tun*`이 이미 캡처하는 트래픽을 계층별로 중복 처리하는 구조였다.

### 6. main.go API 정합성 수정 (`cmd/ebpf-agent/main.go`)

ringbuf 시대의 API(`ConsumeEvents`, `att.Reader`)를 PERCPU_HASH 시대의 API(`ReadFlows`, `att.FlowMap`)로 교체. 코드베이스 전반의 컴파일 에러 해소.

---

## 변경 후 아키텍처

```
┌─────────────────────── Kernel ───────────────────────┐
│                                                       │
│   tc ingress (clsact qdisc) on tun*                   │
│   ┌──────────────────────────────┐                    │
│   │ flow.bpf.c — handle_ingress  │                    │
│   │  data/data_end direct access │                    │
│   │  IPv4/IPv6 → 5-tuple         │                    │
│   └──────────────┬───────────────┘                    │
│                  │ map lookup + +=  (per-CPU, no lock) │
│                  ▼                                     │
│   ┌──────────────────────────────┐                    │
│   │  BPF_MAP_TYPE_PERCPU_HASH    │                    │
│   │  key: flow_key  (44 B)       │                    │
│   │  val: flow_metrics (32 B)    │                    │
│   │  × CPU count                 │                    │
│   └──────────────────────────────┘                    │
└──────────────────────────────────────────────────────┘
                  │  5초마다 map.Iterate()
┌─────────────────▼──────── Userspace (Go) ────────────┐
│  ReadFlows()                                          │
│    per-CPU sum → FlowEvent → chan                     │
│    map.Delete() (카운터 리셋)                          │
│                   ↓                                   │
│  main.go: FormatFlow() → log                          │
└───────────────────────────────────────────────────────┘
```

---

## 재빌드 필요 사항

BPF C 소스(`bpf/flow.bpf.c`, `bpf/common.h`)가 변경되었으므로 반드시 재컴파일이 필요하다.

```bash
cd agents/ebpf-agent
go generate ./internal/bpf/
go build ./...
go test ./...
```

`go generate`는 clang으로 `flow.bpf.c`를 컴파일해 `flow_bpfel.o` 및 `flow_bpfel.go`를 재생성한다.

---

## 향후 개선 후보 (tun 범위 내)

| 항목 | 설명 | 우선순위 |
|------|------|---------|
| IPv6 extension header | nexthdr chain 파싱 (현재는 첫 번째 nexthdr만 봄) | 낮음 |
| ICMP type/code | ports[0]=type, ports[1]=code 인코딩 | 낮음 |
| map 포화 알림 | `max_entries` 도달 시 drop 카운터 노출 | 중간 |
| gRPC transport | FlowEvent를 Central Engine으로 배치 전송 (Phase 4) | 높음 |
