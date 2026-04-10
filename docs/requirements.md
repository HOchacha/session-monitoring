# 요구사항 정의서

## 프로젝트 목표

OpenVPN을 통해 인프라에 진입한 사용자의 패킷을 **직접 캡처·파싱**해서,  
누가 어디에 접근하고 어떤 DNS를 쿼리하는지 실시간으로 감시한다.

> **핵심 수집 방식**: 별도 Exporter가 아닌 eBPF로 패킷을 직접 뜯어낸다.  
> OpenVPN Management Interface는 "CN ↔ VPN IP" 매핑 컨텍스트 획득에만 사용한다.

```
사용자 → OpenVPN 진입 → 가상 라우터 → VXLAN 내부망 → 목적지 VM
  │            │               │              │             │
  └────────────┴───────────────┴──────────────┴─────────────┘
                            연관 분석 엔진
                    (누가, 어디서, 어디로, 얼마나)
```

---

## 1. 데이터 수집 요구사항

### 1-1. Layer 1 — CloudStack Collector

> 사용자-VM-IP 매핑 정보를 제공하는 **정적/동적 컨텍스트**

#### 수집 대상

| 데이터 | 설명 | 업데이트 주기 |
|--------|------|--------------|
| 사용자 계정 (Account/User) | username, UUID, email | 폴링 5분 |
| 가상머신 (VM) | vm_id, vm_name, owner, internal IP | 폴링 1분 |
| Virtual Router | vr_id, associated network, public IP | 폴링 1분 |
| Public IP 할당 | public_ip ↔ vm 매핑, NAT 규칙 | 이벤트 구독 |
| 네트워크 | network_id, VXLAN VNI, CIDR | 폴링 5분 |

#### 수집 방식
- [ ] CloudStack API (listVirtualMachines, listPublicIpAddresses, listRouters)
- [ ] CloudStack Event Bus 구독 (VM.CREATE, VM.STOP, IP.ASSIGN 등)

#### 출력 데이터 (정규화)
```json
{
  "username": "alice",
  "account_id": "uuid",
  "vms": [
    {
      "vm_id": "uuid",
      "name": "web-server-01",
      "internal_ip": "10.100.0.10",
      "network_id": "uuid",
      "vxlan_vni": 1001
    }
  ],
  "public_ips": ["203.0.113.10"],
  "virtual_router_ip": "10.100.0.1"
}
```

---

### 1-2. Layer 2 — OpenVPN Session Tracker

> **역할: 세션 컨텍스트 제공만** — 트래픽 감시는 Layer 3 eBPF가 담당  
> "이 VPN IP가 누구인가?" 라는 질문에 답하기 위한 매핑 테이블 유지

#### 수집 대상

| 데이터 | 설명 | 수집 방식 |
|--------|------|----------|
| 사용자 식별 | Common Name (CN), Real IP | Management Interface |
| VPN 가상 IP | Virtual Address (10.8.0.x) | Management Interface |
| 세션 생명주기 | connected_since, disconnected | Management Interface |

#### 수집 방식
- [x] Management Interface 직접 폴링 (`status 3` 명령, 10초 주기)
- [ ] `CLIENT_CONNECT` / `CLIENT_DISCONNECT` 이벤트 실시간 수신
- [ ] ※ patrickjahns/openvpn_exporter — 비교 참고용으로만 사용 (선택)

#### 현재 구현 메모
- [x] gRPC 연결 실패 시 standalone 자동 폴백
- [x] `--standalone` / `STANDALONE_MODE` 명시 모드
- [x] payload JSON 로그 출력 (`--log-payload`)
- [x] YAML export 필드 선택 (`--export-config`, `EXPORT_CONFIG_PATH`)

#### 유지해야 할 매핑 테이블
```
CN (alice) ←→ VPN Virtual IP (10.8.0.6) ←→ Real IP (203.x.x.x)
```

> 이 테이블이 있어야 eBPF가 잡은 `src_ip=10.8.0.6` 패킷을 alice에 귀속할 수 있다.

#### 출력 데이터
```json
{
  "timestamp": "2026-03-10T07:00:00Z",
  "sessions": [
    {
      "common_name": "alice",
      "real_address": "203.0.113.1:50123",
      "virtual_address": "10.8.0.6",
      "bytes_received": 102400,
      "bytes_sent": 204800,
      "connected_since": "2026-03-10T06:00:00Z",
      "client_id": "1"
    }
  ]
}
```

---

### 1-3. Layer 3 — eBPF Agent

> **핵심 데이터 수집 컴포넌트** — 패킷을 커널에서 직접 파싱해 네트워크 행위를 감시

#### 배포 위치
- OpenVPN 서버 노드 (tun0 인터페이스 — VPN 사용자 트래픽 진입점)
- 컴퓨트 노드들 (VXLAN 인터페이스 — VM 간 내부 통신)
- 네트워크 게이트웨이 노드 (가상 라우터 — 외부 접근)

#### 수집 대상 (캡처 항목)

| 데이터 | 훅 위치 | 상세 내용 |
|--------|---------|----------|
| 패킷 5-tuple | tc ingress/egress (tun0, vxlan+) | src_ip, dst_ip, src_port, dst_port, proto |
| **DNS 쿼리** | tc ingress (UDP/TCP :53) | 쿼리 도메인명, 쿼리 타입(A/AAAA/MX), 응답 IP |
| **TLS SNI** | tc ingress (TCP :443) | Client Hello에서 SNI hostname 추출 |
| **HTTP Host** | tc ingress (TCP :80) | HTTP Host 헤더 추출 |
| TCP 연결 이벤트 | kprobe/tracepoint (tcp_v4_connect, tcp_close) | 연결 수립·종료, RTT |
| VXLAN 내부 패킷 | tc on vxlan 인터페이스 | outer VNI + inner 5-tuple |
| 패킷/바이트 카운터 | BPF map (per-flow) | flow별 집계 |
| 네트워크 네임스페이스 | kprobe / netns ID | VM/컨테이너 식별 |

#### 수집 방식
- [ ] eBPF 프로그램 작성 (C, cilium/ebpf Go 바인딩)
- [ ] BPF ring buffer로 userspace 전달 (low-latency)
- [ ] 집계 후 중앙 엔진 전송 (gRPC stream)

#### DNS 캡처 상세
```
tun0에서 UDP src_port=53 또는 dst_port=53 패킷 캡처
    │
    ├─ DNS Query:    alice(10.8.0.6) → 10.8.0.1:53, QNAME=internal-db.company.internal
    └─ DNS Response: QNAME=internal-db.company.internal → A 10.100.0.50

→ alice가 internal-db.company.internal 를 조회한 사실 기록
→ 응답 IP 10.100.0.50 = CloudStack에서 owner=bob의 DB 서버 → 경보 가능
```

#### TLS SNI 캡처 상세
```
TCP :443 패킷 중 TLS ClientHello 감지
    │
    └─ SNI 필드 파싱: "api.internal.company.com"

→ alice(10.8.0.6) → 10.100.0.10:443, SNI=api.internal.company.com
→ 암호화 내용 없이도 "어디에 접속하려 하는가" 를 확인 가능
```

#### VXLAN 패킷 파싱
```
Outer: src=compute1, dst=compute2, UDP:4789
  └── VXLAN Header: VNI=1001
       └── Inner: src=10.100.0.10, dst=10.100.0.20, TCP:80
```
→ VNI 1001 = network_id → CloudStack에서 소유자 조회

#### 출력 이벤트 타입

**FlowEvent** (패킷 흐름)
```json
{
  "type": "flow",
  "timestamp": "2026-03-10T07:00:00.123Z",
  "node_id": "openvpn-node",
  "src_ip": "10.8.0.6",
  "dst_ip": "10.100.0.10",
  "src_port": 52000,
  "dst_port": 80,
  "protocol": "TCP",
  "packets": 15,
  "bytes": 9800,
  "vxlan_vni": 0
}
```

**DNSEvent** (DNS 쿼리)
```json
{
  "type": "dns",
  "timestamp": "2026-03-10T07:00:00.050Z",
  "node_id": "openvpn-node",
  "src_ip": "10.8.0.6",
  "query": "internal-db.company.internal",
  "query_type": "A",
  "response_ips": ["10.100.0.50"],
  "tx_id": 12345
}
```

**ConnectEvent** (TCP 연결 수립 / TLS SNI)
```json
{
  "type": "tcp_connect",
  "timestamp": "2026-03-10T07:00:00.200Z",
  "node_id": "openvpn-node",
  "src_ip": "10.8.0.6",
  "dst_ip": "10.100.0.50",
  "dst_port": 5432,
  "protocol": "TCP",
  "sni": ""
}
```

---

## 2. 중앙 처리 엔진 요구사항

### 2-1. 데이터 수집 파이프라인

- [ ] 각 에이전트로부터 데이터 수신 (gRPC / NATS)
- [ ] 수신 데이터 버퍼링 및 역압(backpressure) 처리
- [ ] 에이전트 연결 상태 헬스체크

### 2-2. 컨텍스트 상관관계 분석 (핵심 기능)

> **"누가, 어디서, 어디로 패킷을 보내는지"** 를 단일 이벤트로 조합

#### 상관관계 키

```
[VPN Virtual IP] → CloudStack 조회 → [사용자 CN]
[Packet src_ip=10.8.0.6] → VPN session 조회 → [CN=alice]
[Packet dst_ip=10.100.0.10] → CloudStack 조회 → [VM owner=alice, name=web-server-01]
```

#### 생성할 통합 이벤트
```json
{
  "event_id": "uuid",
  "timestamp": "2026-03-10T07:00:00.123Z",
  "user": {
    "common_name": "alice",
    "cloudstack_account": "alice-account",
    "real_ip": "203.0.113.1",
    "vpn_ip": "10.8.0.6"
  },
  "flow": {
    "src_ip": "10.8.0.6",
    "dst_ip": "10.100.0.10",
    "dst_port": 80,
    "protocol": "TCP",
    "bytes": 9800
  },
  "destination": {
    "vm_id": "uuid",
    "vm_name": "web-server-01",
    "owner": "alice",
    "node": "compute-node-01"
  },
  "cross_user_access": false
}
```

- [ ] VPN 세션 캐시 유지 (CN ↔ VPN IP 실시간 업데이트)
- [ ] CloudStack 컨텍스트 캐시 (VM IP ↔ 사용자)
- [ ] **cross_user_access 탐지**: 패킷 출발지 사용자 ≠ 목적지 VM 소유자일 때 플래그

### 2-3. 감시 규칙 (Detection Rules)

| 규칙 | 설명 | 심각도 |
|------|------|--------|
| `CROSS_USER_ACCESS` | A 사용자가 B 사용자의 VM에 접근 | HIGH |
| `DNS_SUSPICIOUS_QUERY` | 타 사용자 소유 내부 도메인 DNS 조회 | HIGH |
| `DNS_EXFILTRATION` | 비정상적으로 긴 서브도메인 or 고빈도 NX 응답 | HIGH |
| `SENSITIVE_PORT_ACCESS` | DB(5432/3306), SSH(22) 등 민감 포트 접근 | MEDIUM |
| `PORT_SCAN` | 동일 src에서 다수 dst port 탐색 | MEDIUM |
| `HIGH_BANDWIDTH` | 단시간 대용량 트래픽 | MEDIUM |
| `UNKNOWN_DESTINATION` | CloudStack에 없는 dst IP로 패킷 | LOW |
| `VPN_SESSION_ANOMALY` | 동일 CN이 다수 IP에서 동시 접속 | HIGH |
| `LATERAL_MOVEMENT` | 내부망 다수 호스트 연속 접근 | HIGH |

- [ ] 규칙 엔진 구현 (pluggable rule interface)
- [ ] 규칙 위반 시 알람 발행
- [ ] 화이트리스트 설정 지원

### 2-4. 저장소

| 데이터 | 저장소 | 보존 기간 |
|--------|--------|----------|
| 통합 플로우 이벤트 | TimescaleDB | 90일 |
| 감시 알람 | PostgreSQL | 1년 |
| CloudStack 메타데이터 | PostgreSQL | 영구 |
| 메트릭 (Prometheus) | VictoriaMetrics | 30일 |

- [ ] 저장소 스키마 설계
- [ ] 파티셔닝 전략 (timestamp 기준)
- [ ] 쿼리 최적화 (src_ip, dst_ip, user 인덱스)

---

## 3. 비기능 요구사항

### 3-1. 성능
- [ ] 에이전트 CPU 사용률 < 5% (per node)
- [ ] 에이전트 메모리 < 100MB (per node)
- [ ] 이벤트 처리 지연 < 500ms (수집 → 상관관계 분석 → 저장)
- [ ] 초당 최소 10,000 flow 이벤트 처리

### 3-2. 신뢰성
- [ ] 에이전트 재시작 시 데이터 유실 없음 (로컬 버퍼링)
- [ ] 중앙 엔진 다운 시 에이전트 버퍼 유지 후 재전송
- [ ] 시계 동기화 (NTP) 필수 — 이벤트 시간 오차 < 100ms

### 3-3. 보안
- [ ] 에이전트 ↔ 엔진 통신 TLS 암호화
- [ ] API 엔드포인트 인증 (JWT)
- [ ] 수집 데이터 접근 권한 분리 (RBAC)
- [ ] 감시 알람 데이터 감사 로그 유지

### 3-4. 운영
- [ ] 각 컴포넌트 systemd 서비스 등록
- [ ] 헬스체크 엔드포인트 (`/health`, `/ready`)
- [ ] 구조화된 로그 출력 (JSON, level 설정 가능)
- [ ] Prometheus 메트릭 자체 노출 (에이전트 + 엔진)

---

## 4. 인터페이스 요구사항

### 4-1. 에이전트 → 엔진 API (gRPC)

```protobuf
service CollectorService {
  // Layer 2: 세션 컨텍스트
  rpc ReportOpenVPNSessions(stream OpenVPNSessionEvent) returns (Ack);

  // Layer 3: 직접 캡처한 패킷 이벤트
  rpc ReportFlowEvents(stream FlowEvent) returns (Ack);
  rpc ReportDNSEvents(stream DNSEvent) returns (Ack);
  rpc ReportConnectEvents(stream ConnectEvent) returns (Ack);

  // Layer 1: CloudStack 메타데이터
  rpc ReportCloudStackContext(CloudStackSnapshot) returns (Ack);
}
```

### 4-2. 엔진 REST API

| 엔드포인트 | 설명 |
|-----------|------|
| `GET /api/v1/sessions` | 현재 활성 VPN 세션 목록 |
| `GET /api/v1/flows?user=alice` | 사용자별 플로우 조회 |
| `GET /api/v1/alerts` | 감시 알람 목록 |
| `GET /api/v1/users/:cn/topology` | 사용자 접근 토폴로지 |
| `GET /metrics` | Prometheus 메트릭 |

### 4-3. 시각화 (Grafana)

- [ ] 대시보드: 현재 접속 중인 VPN 사용자 목록
- [ ] 대시보드: 사용자별 트래픽 플로우 맵
- [ ] 대시보드: 감시 알람 현황
- [ ] 대시보드: 노드별 수집 에이전트 상태

---

## 5. 구현 체크리스트

### Phase 1 — 기반 구축
- [x] OpenVPN Management Interface 활성화 (`localhost:7505`)
- [ ] eBPF 개발 환경 구성 (libbpf, clang, Go toolchain)
- [ ] tun0 인터페이스 기본 패킷 캡처 프로토타입 (tc + BPF)
- [ ] Prometheus + Grafana 설치

### Phase 2 — 에이전트 개발

#### OpenVPN Session Tracker
- [x] Management Interface 폴링 클라이언트 구현
- [x] 세션 파싱 (현재 CLIENT_LIST 중심)
- [ ] ROUTING_TABLE 확장 파싱
- [ ] 세션 연결/해제 실시간 이벤트 수신
- [x] 스냅샷 payload gRPC 전달 (`google.protobuf.Struct`)
- [x] export 필드 선택형 전달(YAML)

#### CloudStack Collector
- [ ] CloudStack API 클라이언트 구현 (Go)
- [ ] VM 목록 주기 폴링
- [ ] Public IP / NAT 규칙 수집
- [ ] Virtual Router 정보 수집
- [ ] 이벤트 스트림 구독
- [ ] 컨텍스트 캐시 관리

#### eBPF Agent
- [ ] tc ingress/egress BPF 프로그램 — 패킷 5-tuple 캡처
- [ ] **DNS 파서**: UDP/TCP :53 패킷에서 QNAME, QTYPE, 응답 IP 추출
- [ ] **TLS SNI 파서**: TCP :443 ClientHello에서 SNI 추출
- [ ] **HTTP Host 파서**: TCP :80 첫 패킷에서 Host 헤더 추출
- [ ] TCP 연결 kprobe (tcp_v4_connect, tcp_close)
- [ ] VXLAN 패킷 파싱 (outer VNI + inner 5-tuple)
- [ ] BPF ring buffer 기반 userspace 전달
- [ ] Userspace 데몬: 이벤트 처리 + gRPC 전송
- [ ] 멀티 인터페이스 동적 어태치 (tun0, vxlan+)
- [ ] 각 노드 배포 스크립트 (systemd + install.sh)

### Phase 3 — 중앙 처리 엔진
- [ ] gRPC 수신 서버 구현
- [ ] 컨텍스트 캐시 계층 구현 (VPN 세션 + CloudStack)
- [ ] 플로우 상관관계 분석 로직 구현
- [ ] 감시 규칙 엔진 구현
- [ ] TimescaleDB 스키마 + 마이그레이션
- [ ] REST API 구현
- [ ] 알람 발행 (Alertmanager 연동)

### Phase 4 — 시각화 및 운영
- [ ] Grafana 대시보드 구성
- [ ] 플로우 토폴로지 시각화
- [ ] 각 컴포넌트 systemd 서비스 파일 작성
- [ ] Docker Compose 통합 테스트 환경 구성
- [ ] 운영 문서 작성

---

## 6. 데이터 흐름 상세

```
[사용자 alice, Real IP: 203.x.x.x]
    │
    ▼ (UDP/1194)
[OpenVPN Server]
    │ tun0 (10.8.0.6 할당)
    │◄──── eBPF Agent (Layer 3): src=10.8.0.6, dst=10.100.0.10, TCP:80
    │◄──── OpenVPN Collector (Layer 2): CN=alice, vpn_ip=10.8.0.6
    │
    ▼ (라우팅)
[Virtual Router / 가상 게이트웨이]
    │◄──── eBPF Agent: VXLAN VNI=1001, src=10.100.0.0/24
    │
    ▼ (VXLAN UDP/4789)
[Compute Node]
    │◄──── eBPF Agent (Layer 3): inner src=10.8.0.6, inner dst=10.100.0.10
    │
    ▼
[VM: web-server-01, IP: 10.100.0.10]
    │◄──── CloudStack Collector (Layer 1): owner=alice, vni=1001

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
모든 이벤트 → Central Engine
→ 상관관계 분석:
  "alice(10.8.0.6) → alice의 VM(10.100.0.10):80" ✓ 정상

만약 dst=10.100.1.20 (bob의 VM):
  "alice(10.8.0.6) → bob의 VM(10.100.1.20):80" ✗ CROSS_USER_ACCESS 알람
```
