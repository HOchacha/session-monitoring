# 시스템 아키텍처

## 전체 구조

```
┌──────────────────────────────────────────────────────────────────────┐
│                        Central Processing Engine                      │
│                                                                       │
│  ┌──────────────┐   ┌──────────────────┐   ┌──────────────────────┐ │
│  │  gRPC Server │   │ Context Cache    │   │   Detection Rules    │ │
│  │  (수신)      │──▶│ - VPN sessions   │──▶│   - CROSS_USER       │ │
│  │             │   │ - CloudStack VMs │   │   - PORT_SCAN        │ │
│  └──────────────┘   │ - IP mappings   │   │   - LATERAL_MOVEMENT │ │
│                     └────────┬─────────┘   └──────────┬───────────┘ │
│                              │                         │             │
│                     ┌────────▼─────────┐   ┌──────────▼───────────┐ │
│                     │  Flow Correlator │   │   Alert Publisher    │ │
│                     │  (3계층 통합)   │   │   (Alertmanager)     │ │
│                     └────────┬─────────┘   └──────────────────────┘ │
│                              │                                        │
│                     ┌────────▼─────────┐   ┌──────────────────────┐ │
│                     │   TimescaleDB    │   │   REST API / Grafana  │ │
│                     │   (플로우 이벤트)│   │   (시각화)           │ │
│                     └──────────────────┘   └──────────────────────┘ │
└──────────────────────────────────────────────────────────────────────┘
         ▲                    ▲                         ▲
         │ gRPC               │ gRPC                    │ gRPC
         │                    │                         │
┌────────┴──────┐   ┌─────────┴──────┐       ┌─────────┴──────────┐
│  OpenVPN      │   │  CloudStack    │       │  eBPF Agent        │
│  Collector    │   │  Collector     │       │  (각 노드 배포)     │
│               │   │                │       │                     │
│  - Mgmt IF    │   │  - CS API 폴링 │       │  - XDP/tc 훅       │
│    폴링       │   │  - 이벤트 구독 │       │  - VXLAN 파싱      │
│  - 세션 파싱  │   │                │       │  - BPF map 집계    │
└───────────────┘   └────────────────┘       └────────────────────┘
  [OpenVPN Node]      [CloudStack API]          [모든 컴퓨트 노드]
```

---

## 컴포넌트 상세

### OpenVPN Session Tracker (`agents/openvpn-exporter/`)

**역할: 세션 컨텍스트 제공만** — 트래픽/패킷 감시는 eBPF Agent가 담당.  
Management Interface에서 "CN ↔ VPN IP" 매핑 테이블을 유지해 엔진에 제공한다.

> ※ `patrickjahns/openvpn_exporter`는 비교 참고용. 핵심 경로가 아님.

**Management Interface 통신**
```
TCP connect → localhost:7505
→ status 3
← CLIENT_LIST,alice,203.x.x.x:50123,10.8.0.6,...
   END

→ 엔진 캐시 업데이트: { "10.8.0.6": { cn: "alice", real_ip: "203.x.x.x" } }
```

**런타임 모드 (현재 구현)**
- `grpc` 모드: 수집 후 엔진으로 전송
- `standalone` 모드: 수집/로그만 수행 (`--standalone`)
- gRPC 접속 실패 시 자동 standalone 폴백

**Export 필드 정책**
- YAML 설정(`--export-config`)으로 payload 필드를 선별
- `snapshot_fields`: 상위 필드 선택
- `session_fields`: `sessions[]` 내부 필드 선택

**이 매핑이 없으면**: eBPF가 `src_ip=10.8.0.6` 패킷을 잡아도 누구인지 알 수 없음.

---

### CloudStack Collector (`agents/cloudstack-collector/`)

CloudStack API를 통해 사용자·VM·IP 메타데이터를 수집하고 캐시를 유지한다.

**API 호출 목록**
| API | 설명 | 주기 |
|-----|------|------|
| `listVirtualMachines` | VM 목록, IP, 소유자 | 1분 |
| `listPublicIpAddresses` | Public IP 할당 | 1분 |
| `listRouters` | Virtual Router 정보 | 5분 |
| `listNetworks` | 네트워크 CIDR, VNI | 5분 |
| `listAccounts` | 사용자 계정 정보 | 5분 |
| `listEvents` (event listener) | 실시간 상태 변화 | 스트림 |

**IP 해석 순서**
```
dst_ip 수신
    │
    ├─ VPN 대역(10.8.0.0/24)? → OpenVPN session 조회 → CN
    ├─ 내부 VM IP?            → CloudStack listVM 조회 → owner
    ├─ Public IP?             → listPublicIpAddresses → NAT 대상 VM
    └─ 알 수 없음             → UNKNOWN_DESTINATION 알람
```

---

### eBPF Agent (`agents/ebpf-agent/`)

**핵심 컴포넌트** — 커널에서 패킷을 직접 파싱해 DNS 쿼리, 시스템 접근, 패킷 흐름을 감시한다.

**eBPF 프로그램 구조**
```
tun0 (OpenVPN)
  ├─ tc ingress BPF ──▶ DNS 파서 (UDP/TCP :53)  ──▶ ring buffer → DNSEvent
  ├─ tc ingress BPF ──▶ SNI 파서 (TCP :443)     ──▶ ring buffer → ConnectEvent
  ├─ tc ingress BPF ──▶ HTTP 파서 (TCP :80)     ──▶ ring buffer → ConnectEvent
  └─ tc ingress BPF ──▶ Flow 집계 (전체 포트)   ──▶ BPF map    → FlowEvent

vxlan+ (VXLAN 인터페이스)
  └─ tc ingress BPF ──▶ VNI + inner 5-tuple    ──▶ BPF map    → FlowEvent

kprobe: tcp_v4_connect / tcp_close             ──▶ ring buffer → ConnectEvent

Userspace daemon (Go)
  └─ ring buffer / map poll → gRPC stream → Engine
```

**DNS 파싱 로직**
```
UDP src_port=53 또는 dst_port=53 캡처
    │
    ├─ Query 패킷:    TX_ID + QNAME + QTYPE 추출
    │    예) 10.8.0.6 → 10.8.0.1:53, QNAME="db.internal", QTYPE=A
    │
    └─ Response 패킷: TX_ID 매칭 + Answer RR에서 응답 IP 추출
         예) 10.8.0.1:53 → 10.8.0.6, QNAME="db.internal" → [10.100.0.50]

→ DNSEvent: { user=alice, query="db.internal", response_ips=["10.100.0.50"] }
→ 응답 IP가 타 사용자 소유 VM이면 → DNS_SUSPICIOUS_QUERY 알람
```

**TLS SNI 파싱 로직**
```
TCP :443 패킷 첫 세그먼트에서 TLS Record 감지
    │
    └─ ContentType=0x16 (Handshake) + HandshakeType=0x01 (ClientHello)
         → Extensions 탐색 → SNI extension (type=0x0000)
         → server_name 추출: "api.internal.company.com"

→ ConnectEvent: { user=alice, dst_ip=10.100.0.10, dst_port=443, sni="api.internal.company.com" }
```

**VXLAN 파싱 로직**
```
UDP dst:4789 캡처
    ├─ Outer IP: 노드 간 통신 식별
    ├─ VXLAN Header: VNI 추출 → CloudStack network_id 매핑
    └─ Inner Ethernet Frame:
           ├─ Inner IP src/dst
           └─ L4 port, protocol
```

**BPF Map 구조**
```c
// flow 집계용 (5초마다 flush)
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  protocol;
    __u32 vxlan_vni;  // 0 = non-VXLAN
};

struct flow_value {
    __u64 packets;
    __u64 bytes;
    __u64 first_seen_ns;
    __u64 last_seen_ns;
};

// DNS 쿼리 추적용 (TX_ID 기반 query-response 매칭)
struct dns_query_key {
    __u32 src_ip;
    __u16 tx_id;
};

struct dns_query_value {
    char  qname[255];
    __u16 qtype;
    __u64 queried_at_ns;
};
```

---

### Central Processing Engine (`engine/`)

#### Flow Correlator (`engine/correlator/`)

3계층 컨텍스트를 조합해 단일 통합 이벤트를 생성한다.

```
입력: FlowEvent { src_ip=10.8.0.6, dst_ip=10.100.0.10, dst_port=80 }

1. src_ip=10.8.0.6 → VPN session 캐시 조회
   → { CN="alice", real_ip="203.x.x.x" }

2. dst_ip=10.100.0.10 → CloudStack 캐시 조회
   → { vm_id="uuid", name="web-server-01", owner="alice", vni=1001 }

3. 통합 이벤트 생성:
   → user=alice, flow=10.8.0.6→10.100.0.10:80, destination=web-server-01(alice소유)
   → cross_user_access = (alice ≠ alice) = false ✓
```

#### Detector (`engine/detector/`)

룰 기반 이상 탐지. 각 규칙은 `Rule` 인터페이스를 구현한다.

```go
type Rule interface {
    Name() string
    Evaluate(event *CorrelatedEvent) (Alert, bool)
}
```

| 규칙 | 조건 | 심각도 |
|------|------|--------|
| CrossUserAccess | flow.user ≠ destination.owner | HIGH |
| DNSSuspiciousQuery | DNS response IP가 타 사용자 VM | HIGH |
| DNSExfiltration | NX 응답 고빈도 or 서브도메인 길이 이상 | HIGH |
| SensitivePortAccess | dst_port ∈ {22,3306,5432,6379,27017} | MEDIUM |
| PortScan | 동일 src, 10초 내 10개 이상 다른 dst_port | MEDIUM |
| LateralMovement | 동일 src, 1분 내 5개 이상 다른 dst_ip | HIGH |
| HighBandwidth | 1분 내 1GB 초과 | MEDIUM |
| UnknownDestination | dst_ip가 CloudStack에 없음 | LOW |
| VPNSessionAnomaly | 동일 CN, 다른 real_ip에서 동시 세션 | HIGH |

---

## 데이터 흐름 상세 (End-to-End)

```
시나리오: alice가 VPN 접속 후 web-server-01(TCP:80)에 접근

1. alice → OpenVPN Server (UDP:1194)
   └─ OpenVPN: CN=alice, 가상IP 10.8.0.6 할당

2. OpenVPN Session Tracker (10초 주기 폴링)
   └─ Management IF → SESSION: alice=10.8.0.6
   └─ gRPC → Engine: UpdateVPNSession(alice, 10.8.0.6)

3. alice가 DB 서버를 찾기 위해 DNS 쿼리:
   └─ 10.8.0.6 → 10.8.0.1:53 QNAME="internal-db.company.internal"
   └─ tun0 tc BPF가 DNS 패킷 캡처 → DNSEvent
   └─ gRPC → Engine: DNSEvent(alice, "internal-db.company.internal", ["10.100.0.10"])

4. alice 패킷: 10.8.0.6 → 10.100.0.10:443 (TLS)
   └─ tun0 tc BPF가 TLS ClientHello 캡처 → SNI 추출
   └─ ConnectEvent(alice, 10.100.0.10:443, sni="internal-db.company.internal")
   └─ BPF flow map 누적: {src=10.8.0.6, dst=10.100.0.10, dport=443}
   └─ 5초마다 flush → gRPC → Engine: FlowEvent(...)

4. Engine Correlator 처리:
   - 10.8.0.6 → alice (VPN 캐시)
   - 10.100.0.10 → web-server-01, owner=alice (CS 캐시)
   - CorrelatedEvent 생성 (cross_user_access=false)
   - TimescaleDB 저장

5. Grafana 조회:
   - "alice의 현재 접근 목록"
   - "10.100.0.10에 접근한 사용자들"
```

---

## 배포 구성

### 단일 노드 (개발/테스트)

```
docker-compose up
  ├─ openvpn-exporter (포트 9176)
  ├─ prometheus (포트 9090)
  ├─ grafana (포트 3000)
  ├─ engine (포트 8080/gRPC, 9090/REST)
  ├─ timescaledb (포트 5432)
  └─ alertmanager (포트 9093)
```

### 멀티 노드 (프로덕션)

```
[OpenVPN Node]
  └─ openvpn-exporter (systemd)
  └─ ebpf-agent (systemd)

[CloudStack Node / 별도 서버]
  └─ cloudstack-collector (systemd)

[각 Compute Node]
  └─ ebpf-agent (systemd)

[Monitoring Server]
  └─ engine (docker or systemd)
  └─ timescaledb
  └─ prometheus + grafana
  └─ alertmanager
```

---

## 기술 스택

| 계층 | 기술 선택 | 이유 |
|------|----------|------|
| 에이전트 언어 | Go | eBPF 라이브러리(cilium/ebpf), 적은 메모리 |
| eBPF | cilium/ebpf + libbpf | Go 네이티브 통합 |
| 에이전트 통신 | gRPC (streaming) | 효율적 스트리밍, protobuf 직렬화 |
| 시계열 DB | TimescaleDB | PostgreSQL 호환, 시계열 최적화 |
| 메타데이터 DB | PostgreSQL (TimescaleDB 내) | 동일 인스턴스 활용 |
| 메트릭 | Prometheus + VictoriaMetrics | 장기 보존 |
| 시각화 | Grafana | 범용성, 플러그인 생태계 |
| 알람 | Alertmanager | Prometheus 네이티브 연동 |
