# eBPF Agent (Layer 3)

OpenVPN/CloudStack 컨텍스트와 결합할 네트워크 이벤트를 커널에서 직접 수집하는 에이전트.
userspace는 Go(`cilium/ebpf`)로 구현하고, eBPF 프로그램은 CO-RE로 빌드한다.

> 구현 상세는 [IMPLEMENTATION.md](IMPLEMENTATION.md)를 참고한다.

---

## 빠른 시작

### 사전 요구사항

| 항목 | 최소 버전 | 확인 명령 |
|------|-----------|-----------|
| Linux 커널 (BTF 지원) | 5.8+ | `ls /sys/kernel/btf/vmlinux` |
| Go | 1.24+ | `go version` |
| clang | 14+ (권장 18) | `clang --version` |
| bpftool | 5.8+ | `bpftool version` |
| libbpf 헤더 | — | `ls /usr/include/bpf/bpf_helpers.h` |

### 빌드

```bash
cd agents/ebpf-agent

# 1. BPF 오브젝트 코드 생성 (bpf2go)
go generate ./internal/bpf/

# 2. Go 바이너리 빌드
go build -o ebpf-agent ./cmd/ebpf-agent/
```

### 실행

```bash
# root 권한 필요 (BPF 로드 + tc 어태치)
sudo ./ebpf-agent
```

기본 동작:
1. `configs/agents/ebpf-agent.yaml` 로드
2. 설정된 프리픽스에 매칭되는 네트워크 인터페이스 탐색
3. 각 인터페이스에 tc/ingress BPF 프로그램 어태치
4. ringbuf에서 FlowEvent를 읽어 stdout에 로그 출력
5. `Ctrl+C` (SIGINT) 또는 SIGTERM으로 정상 종료 (tc 필터 자동 제거)

> **참고:** L3 디바이스(tun — raw IP)와 L2 디바이스(vnet/cloudbr — Ethernet)를 자동 감지합니다.

출력 예시:
```
2026/04/08 14:08:24 ebpf-agent starting (config=../../configs/agents/ebpf-agent.yaml)
2026/04/08 14:08:24 attach candidates: [tun0]
2026/04/08 14:08:24 attached tc/ingress on tun0
2026/04/08 14:08:24 ringbuf consumer starting
2026/04/08 14:08:24 flow: 10.8.0.2:52670 → 199.232.211.52:443 proto=6 bytes=52 if=4
2026/04/08 14:08:24 flow [vlan=100]: 192.168.10.1:40000 → 192.168.10.2:443 proto=6 bytes=800 if=3
2026/04/08 14:08:24 flow [vxlan vni=5494 outer=10.10.0.14→10.10.0.15]: 10.100.0.5:49000 → 10.200.0.1:8080 proto=6 bytes=1400 if=7
```

### 설정

설정 파일 탐색 순서:
1. `EBPF_AGENT_CONFIG_PATH` 환경변수
2. `configs/agents/ebpf-agent.yaml` (상대경로)
3. `../../configs/agents/ebpf-agent.yaml`
4. `/etc/openvpn-monitoring/ebpf-agent.yaml`

```yaml
# configs/agents/ebpf-agent.yaml
agent:
  name: ebpf-agent

interfaces:
  include_prefixes: [vnet, cloudbr, brvx, tun, vxlan]
  exclude_prefixes: [lo, docker, veth, virbr, cni, flannel, kube]
  require_up: true
```

| 필드 | 설명 | 기본값 |
|------|------|--------|
| `agent.name` | 에이전트 이름 (로그 식별용) | `ebpf-agent` |
| `interfaces.include_prefixes` | 어태치 대상 인터페이스 접두사 | `[vnet, cloudbr, brvx, tun, vxlan]` |
| `interfaces.exclude_prefixes` | 제외할 인터페이스 접두사 | `[lo, docker, veth, virbr, ...]` |
| `interfaces.require_up` | UP 상태 인터페이스만 대상 | `true` |

### 테스트

```bash
go test ./... -v
```

### 수동으로 tc 필터 확인/제거

```bash
# 어태치된 BPF 필터 확인
sudo tc filter show dev tun0 ingress

# 수동 제거 (비정상 종료 시)
sudo tc filter del dev tun0 ingress
sudo tc qdisc del dev tun0 clsact
```

---

## 프로젝트 목표

- 인프라 내부망 VM 트래픽의 흐름을 실시간 관찰
- 사용자 요청 목적지(도메인/IP/포트) 컨텍스트를 Decision Engine으로 전송
- OpenVPN Session Agent(CN ↔ VPN IP 매핑)와 상관분석 가능하도록 표준 이벤트 스키마 유지

## 범위 (MVP)

- tc ingress 기준 FlowEvent 수집 (`vnet*`, `cloudbr*`, `brvx*`, `tun0`, `vxlan*`)
- 5-tuple + bytes/packets + ifindex + timestamp
- ringbuf → Go userspace → stdout 로그 (gRPC 전송은 Phase 4)
- CO-RE 기반 단일 바이너리 배포 가능 구조

## 디렉토리 구조

```
agents/ebpf-agent/
├── bpf/
│   ├── common.h           # C/Go 공유 구조체 (flow_event)
│   ├── flow.bpf.c         # eBPF tc ingress 프로그램
│   └── vmlinux.h          # 커널 BTF 타입 헤더
├── cmd/ebpf-agent/
│   ├── main.go            # 진입점 (파이프라인 통합)
│   ├── config.go          # YAML 설정 로딩/검증
│   └── config_test.go
├── internal/
│   ├── bpf/
│   │   ├── generate.go    # go:generate bpf2go 지시
│   │   ├── flow_bpfel.go  # 생성된 Go 바인딩
│   │   └── flow_bpfel.o   # 컴파일된 BPF ELF
│   ├── collector/
│   │   ├── interfaces.go  # 인터페이스 탐색
│   │   ├── interfaces_test.go
│   │   ├── loader.go      # BPF 로드 + tc 어태치
│   │   ├── consumer.go    # ringbuf 이벤트 소비
│   │   └── consumer_test.go
│   └── events/
│       └── types.go       # FlowEvent Go 구조체
├── go.mod
└── go.sum
```

## 인터페이스 어태치 전략

CloudStack 노드의 데이터 경로:

| 우선순위 | 프리픽스 | 용도 |
|----------|----------|------|
| 1순위 | `vnet*` | VM vNIC 경계 — VM 단위 관찰 정확도 최고 |
| 2순위 | `brvx*` | VXLAN decap 이후 브리지 — overlay VM 보완 관찰 |
| 3순위 | `cloudbr*` | 브리지 레벨 — 누락 보완용 (중복 가능) |
| 4순위 | `tun0` | OpenVPN 노드에서 VPN 진입 트래픽 |
| 선택 | `vxlan*` | 노드 간 오버레이 (outer UDP/4789) |

```
Underlay NIC → cloudbr → vnet* (VM)
                       → vxlan* → brvx* → vnet* (overlay VM)
OpenVPN → tun0
```

### Topology Diagram

```mermaid
flowchart LR
  subgraph U[Underlay NIC]
    ENP0[enp134s0f0]
    ENP1[enp134s0f1]
  end

  subgraph B[Bridge Domains]
    CBR0[cloudbr0\n10.15.0.14/24]
    CBR1[cloudbr1\n10.10.0.14/16]
    C0[cloud0\n169.254.0.1/16]
    BRVX[brvx-5494\nmtu 1450]
  end

  subgraph O[Overlay]
    VX[vxlan5494\n(master -> brvx-5494)]
  end

  subgraph VC1[VM TAP on cloudbr1]
    V0[vnet0]
    V2[vnet2]
    V3[vnet3]
    V4[vnet4]
    V5[vnet5]
    V6[vnet6]
    V9[vnet9]
  end

  subgraph VC0[VM TAP on cloud0]
    V8[vnet8]
  end

  subgraph VO[VM TAP on brvx-5494]
    V7[vnet7\nmtu 1450]
    V10[vnet10\nmtu 1450]
  end

  ENP0 --> CBR1
  ENP1 --> CBR0

  CBR1 --> V0
  CBR1 --> V2
  CBR1 --> V3
  CBR1 --> V4
  CBR1 --> V5
  CBR1 --> V6
  CBR1 --> V9

  C0 --> V8

  VX --> BRVX
  BRVX --> V7
  BRVX --> V10

  classDef pri fill:#dff3e3,stroke:#2f7d32,stroke-width:2px,color:#111;
  classDef sec fill:#e7f0ff,stroke:#1f4e99,stroke-width:1.5px,color:#111;
  classDef opt fill:#fff3df,stroke:#9a6700,stroke-width:1.5px,color:#111;

  class V0,V2,V3,V4,V5,V6,V7,V8,V9,V10 pri;
  class BRVX,CBR0,CBR1 sec;
  class VX opt;
```

## 로드맵

| Phase | 상태 | 내용 |
|-------|------|------|
| 0. Environment | ✅ | BTF, clang, bpftool, Go 확인 |
| 1. Repo Bootstrap | ✅ | go.mod, 디렉토리 구조, bpf2go 파이프라인 |
| 2. eBPF Program | ✅ | L3/L2 자동 감지, IPv4/IPv6 → TCP/UDP 파서, VXLAN inner+outer, 802.1Q VLAN |
| 3. Userspace Collector | ✅ | BPF 로드, tc 어태치, ringbuf 소비, 정상 종료 |
| 4. Event Transport | 🔲 | gRPC 클라이언트, 배칭, 백프레셔 |
| 5. Protocol Parsers | 🔲 | DNS, TLS SNI, HTTP Host |
| 6. Hardening | 🔲 | map 튜닝, 고부하 테스트, systemd 배포 |

## Event Schema

### FlowEvent (구현 완료)
| 필드 | 타입 | 설명 |
|------|------|------|
| `ts_unix_nano` | uint64 | 커널 타임스탬프 (nanoseconds) |
| `ifindex` | uint32 | 수신 인터페이스 인덱스 |
| `ip_version` | uint8 | 4 또는 6 (VXLAN시 inner IP) |
| `protocol` | uint8 | IPPROTO (6=TCP, 17=UDP, ...) |
| `src_ip` | [16]byte | 출발지 IP (VXLAN시 inner) |
| `dst_ip` | [16]byte | 목적지 IP (VXLAN시 inner) |
| `src_port` | uint16 | 출발지 포트 |
| `dst_port` | uint16 | 목적지 포트 |
| `vlan_id` | uint16 | 802.1Q VLAN ID (0 = untagged) |
| `vni` | uint32 | VXLAN Network Identifier (0 = non-VXLAN) |
| `outer_src_ip` | [16]byte | VXLAN 터널 엔드포인트 src |
| `outer_dst_ip` | [16]byte | VXLAN 터널 엔드포인트 dst |
| `bytes` | uint64 | 패킷 크기 (L2 기준) |
| `packets` | uint64 | 패킷 수 (현재 항상 1) |

### DNSEvent (Phase 5 예정)
- `query`, `qtype`, `answers`, `rcode`, `src_ip`, `dst_ip`

### ConnectEvent (Phase 5 예정)
- `dst_ip`, `dst_port`, `sni`, `http_host`
