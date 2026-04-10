# OpenVPN Multi-Layer Network Monitoring System

## 프로젝트 개요

OpenVPN을 통해 인프라에 진입한 사용자의 패킷이 **어디서 왔고 어디로 가는지**,  
CloudStack / OpenVPN / eBPF 3개 계층의 데이터를 통합해 실시간으로 감시하는 시스템.

> **상세 요구사항 & 구현 체크리스트:** [docs/requirements.md](docs/requirements.md)

## 현재 구현 상태 (2026-03-12)

- Layer 2 `openvpn-exporter`(Go) 동작 확인 완료
- OpenVPN Management Interface(`127.0.0.1:7505`) 폴링 수집 완료
- 수집 항목: `CN`, `Real Address`, `Virtual Address`, 세션별 bytes, 집계 bytes
- gRPC 비연결 시 자동 `standalone` 폴백 지원
- `--standalone` 명시 모드 지원
- 수집 payload JSON 로그 출력 지원 (`--log-payload`)
- YAML 기반 export 필드 선택 지원 (`--export-config`)

### 핵심 목표
- OpenVPN 진입점에서 사용자 식별 (CN ↔ VPN IP ↔ Real IP)
- 멀티 노드에 걸친 패킷 흐름 추적 (eBPF Agent)
- CloudStack · OpenVPN · eBPF 3계층 컨텍스트 통합 분석
- 실시간 이상 행동 감시 (Cross-user access, Lateral movement 등)

## 시스템 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                     Central Processing Engine                │
│  ┌──────────────────────────────────────────────────────┐  │
│  │         Flow Correlation & Analysis Engine           │  │
│  │  - User session tracking                             │  │
│  │  - Packet flow correlation                           │  │
│  │  - Network behavior analysis                            │  │
│  │  - Anomaly detection                                 │  │
│  └──────────────────────────────────────────────────────┘  │
│                           ▲                                  │
│                           │                                  │
│              ┌────────────┼────────────┐                    │
│              │            │            │                    │
└──────────────┼────────────┼────────────┼────────────────────┘
               │            │            │
    ┌──────────▼───┐   ┌───▼────────┐   ┌▼──────────────┐
    │ CloudStack   │   │  OpenVPN   │   │  eBPF/BPF     │
    │  Collector   │   │  Collector │   │  Agent        │
    └──────────────┘   └────────────┘   └───────────────┘
         Layer 1           Layer 2          Layer 3
```

## 데이터 수집 계층

### Layer 1: CloudStack Context
**수집 대상:**
- 사용자 계정 정보 (Account, User)
- 가상 머신 정보 (VM instances)
- Virtual Router 정보
- Public IP 할당 정보
- 네트워크 토폴로지

**수집 방법:**
- CloudStack API 폴링
- Event notification 구독

**목적:**
- 사용자-VM 매핑
- VM-IP 매핑
- 네트워크 구조 파악

### Layer 2: OpenVPN Context
**수집 대상:**
- 사용자 연결 정보 (Common Name, Real Address)
- VPN 클라이언트 가상 IP (Virtual Address)
- 바이트 송수신량
- 연결 시간 및 세션 정보
- 라우팅 테이블

**수집 방법:**
- OpenVPN Management Interface (localhost:7505)
- `status 3` 폴링 (`agents/openvpn-exporter`)
- 필요 시 standalone 모드로 수집만 수행
- YAML 설정으로 export 필드 선별

**목적:**
- VPN 사용자 식별
- 진입 트래픽 추적
- 사용자-VPN IP 매핑

### Layer 3: Kernel/Network Context (eBPF/BPF)
**수집 대상:**
- 패킷 메타데이터 (src/dst IP, port, protocol)
- VXLAN 터널 정보
- 네트워크 네임스페이스 정보
- 커널 레벨 통계
- TCP/UDP 연결 상태

**수집 방법:**
- eBPF 프로그램 (XDP, tc, tracepoint)
- BPF maps를 통한 커널-유저스페이스 통신
- Packet capture hooks

**목적:**
- 실제 패킷 흐름 추적
- VXLAN 오버레이 네트워크 가시성
- 네트워크 성능 메트릭

## 데이터 흐름

```
User → OpenVPN Server → Virtual Router → VXLAN Network → Target VM
  │           │                │              │              │
  │           ▼                ▼              ▼              ▼
  │   Layer 2 Collector  Layer 3 Agent  Layer 3 Agent  Layer 1 Info
  │           │                │              │              │
  └───────────┴────────────────┴──────────────┴──────────────┘
                                │
                                ▼
                    Central Processing Engine
                                │
                                ▼
                        Correlation Result
                    (User → Flow → Destination)
```

## 핵심 기능 요구사항

### 1. 사용자 식별 및 추적
- OpenVPN CN(Common Name)을 통한 사용자 식별
- CloudStack 사용자 정보와 매핑
- 세션 생명주기 관리

### 2. 패킷 흐름 상관관계 분석
- VPN Virtual IP → Real IP 매핑
- Source IP → Destination IP 추적
- VXLAN 터널 내부 흐름 가시화
- 멀티 홉 네트워크 경로 재구성

### 3. 멀티 노드 데이터 수집
- 각 노드에 경량 에이전트 배포
- 중앙 집중식 데이터 수집
- 시계 동기화 (NTP)
- 분산 추적 (Distributed Tracing)

### 4. 실시간 감시 및 분석
- 이상 트래픽 패턴 탐지
- 접근 제어 정책 위반 감지
- 대시보드 시각화
- 알람 및 알림

## 기술 스택

### 데이터 수집
- **OpenVPN Session Agent**: `agents/openvpn-exporter` (custom Go collector)
- **eBPF**: libbpf, bcc, or cilium/ebpf (Go)
- **CloudStack API Client**: Python/Go SDK

### 데이터 전송
- **Message Queue**: Kafka or NATS
- **Time Series DB**: Prometheus + VictoriaMetrics
- **Log Aggregation**: Vector or Fluentd

### 데이터 처리
- **Stream Processing**: Apache Flink or Kafka Streams
- **Correlation Engine**: Custom Go service
- **Storage**: TimescaleDB (시계열), PostgreSQL (메타데이터)

### 시각화 및 모니터링
- **Dashboard**: Grafana
- **Alerting**: Alertmanager
- **Tracing**: Jaeger or Tempo

## 프로젝트 구조

```
openvpn-monitoring/
├── README.md                        # 이 파일
├── docs/
│   ├── requirements.md              # 상세 요구사항 & 구현 체크리스트
│   └── architecture.md              # 상세 아키텍처 문서
├── agents/                          # 데이터 수집 에이전트
│   ├── cloudstack-collector/        # Layer 1: CloudStack API 수집기
│   ├── openvpn-exporter/            # Layer 2: OpenVPN 세션 수집
│   └── ebpf-agent/                  # Layer 3: eBPF 패킷 캡처 에이전트
├── engine/                          # 중앙 처리 엔진
│   ├── correlator/                  # 3계층 컨텍스트 상관관계 분석
│   ├── detector/                    # 이상 행동 감시 규칙 엔진
│   └── api/                         # REST / gRPC API
├── deployments/
│   ├── docker-compose/              # 로컬 통합 테스트 환경
│   ├── kubernetes/                  # 프로덕션 배포
│   └── systemd/                     # 에이전트 서비스 파일
├── configs/
│   ├── agents/                      # 에이전트 설정
│   └── engine/                      # 엔진 설정
└── scripts/
    ├── setup.sh
    └── install-agent.sh
```

## 구현 단계

> 상세 체크리스트는 [docs/requirements.md](docs/requirements.md) 참조

### Phase 1 — 기반 구축 (현재)
- [x] OpenVPN Management Interface 활성화 (`localhost:7505`)
- [ ] patrickjahns/openvpn_exporter 설치
- [ ] Prometheus 설치 및 scrape 설정
- [ ] Grafana 설치 및 Prometheus datasource 연결

### Phase 2 — 에이전트 개발
- [x] OpenVPN Collector (Management Interface 폴링, 세션 파싱)
- [x] OpenVPN Collector standalone 폴백 및 payload 로그
- [x] OpenVPN Collector YAML export 필드 설정
- [ ] CloudStack Collector (VM, IP, Virtual Router 수집)
- [ ] eBPF Agent (XDP/tc 패킷 캡처, VXLAN 파싱)
- [ ] 공통 데이터 스키마 정의 (Protobuf)

### Phase 3 — 중앙 처리 엔진
- [ ] gRPC 수신 서버
- [ ] 3계층 컨텍스트 상관관계 분석 로직
- [ ] 감시 규칙 엔진 (CROSS_USER_ACCESS, LATERAL_MOVEMENT 등)
- [ ] TimescaleDB 저장소
- [ ] REST API

### Phase 4 — 시각화 및 운영
- [ ] Grafana 대시보드 (활성 세션, 플로우 맵, 알람 현황)
- [ ] Alertmanager 연동
- [ ] systemd 서비스 패키징
- [ ] 운영 문서

## 설정 정보 (현재)

### OpenVPN 서버
- Management Interface: `localhost:7505`
- Status File: `/run/openvpn-server/status-server.log`
- Server IP: `10.10.10.168:1194`
- VPN Network: `10.8.0.0/24`

### OpenVPN Exporter 실행 예시

```bash
cd agents/openvpn-exporter
go build -o bin/openvpn-session-agent ./cmd/session-agent

./bin/openvpn-session-agent \
    --management-addr 127.0.0.1:7505 \
    --standalone \
    --export-config ../../configs/agents/openvpn-exporter.yaml \
    --interval 10s
```

관련 문서: `agents/openvpn-exporter/README.md`

### 노드 현황
| 역할 | 호스트 | 에이전트 |
|------|--------|---------|
| OpenVPN 서버 | hocha-monitoring | openvpn-exporter, ebpf-agent |
| CloudStack | 설정 필요 | cloudstack-collector |
| 컴퓨트 노드 | TBD | ebpf-agent |

