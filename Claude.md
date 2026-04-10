# OpenVPN Monitoring - 작업 맥락 기록

> **마지막 업데이트:** 2026-04-08

## 프로젝트 개요

OpenVPN 사용자의 패킷을 다계층 인프라(CloudStack, OpenVPN, eBPF)에서 실시간 추적하는 네트워크 모니터링 시스템.
핵심 질문: **"누가 어디서 어디로 가는지?"**

### 3계층 아키텍처

| 계층 | 컴포넌트 | 언어 | 상태 |
|------|----------|------|------|
| L3: 패킷 캡처 | eBPF Agent | Go + eBPF (CO-RE) | ✅ Phase 2-3 + VXLAN/VLAN/L3 |
| L2: 세션 추적 | OpenVPN Session Agent | Go | ✅ MVP 완료 |
| L1: VM 컨텍스트 | CloudStack Collector | Go (예정) | ❌ 미시작 |
| 통합 | Central Engine | Go | ❌ 미시작 |

---

## 컴포넌트별 진행 상황

### 1. OpenVPN Session Agent (`agents/openvpn-exporter/`) — ✅ 완료

- Management Interface 클라이언트 (TCP 연결, `status 3` 폴링, kill 기능)
- Status3 파서 (CLIENT_LIST 파싱, CN/IP/Bytes/Cipher 추출)
- gRPC Shipper (Engine으로 스냅샷 전송)
- Export Config (YAML 기반 필드 필터링)
- Main Loop (주기적 수집, standalone/gRPC 모드, kill 모드)
- **단위 테스트 전체 통과**
- systemd 서비스 파일 배포 준비 완료

### 2. eBPF Agent (`agents/ebpf-agent/`) — ✅ Phase 2-3 + VXLAN/VLAN/L3

**완료된 부분:**
- Config 시스템 (YAML 로딩, 검증, 환경변수 오버라이드)
- Interface Discovery (`vnet`, `cloudbr`, `brvx`, `tun`, `vxlan` 프리픽스 매칭)
- Event 타입 정의 (`FlowEvent` 구조체 — 5-tuple + VXLAN + VLAN, 104B)
- **Phase 2: BPF 패킷 파서 완료** (`flow.bpf.c`)
  - **L3/L2 자동 감지**: `first_byte[7:4]` + `skb->protocol` 교차 검증
    - L3 디바이스(tun): raw IP 패킷 직접 파싱 (Ethernet 헤더 없음)
    - L2 디바이스(vnet/cloudbr): Ethernet → IP 파싱
  - IPv4/IPv6 파싱, TCP/UDP 5-tuple 추출
  - IHL 동적 계산 (IPv4), extension header 미추적 (IPv6 MVP)
  - **802.1Q VLAN 지원**: EtherType 0x8100/0x88A8 감지, 12-bit VLAN ID 추출
  - **VXLAN inner+outer 동시 파싱**: UDP:4789 → VNI 추출, inner L3/L4 재귀 파싱
  - ringbuf으로 `FlowEvent` 전송
- **Phase 3: Userspace 컴렉터 완료**
  - `internal/bpf/` — bpf2go 코드 생성 (cilium/ebpf v0.21.0)
  - `internal/collector/loader.go` — BPF 로드, clsact qdisc 생성, tc ingress 필터 어태치
  - `internal/collector/consumer.go` — ringbuf 이벤트 소비, binary.Read 디코딩
  - `cmd/ebpf-agent/main.go` — 전체 파이프라인 통합 (config → discovery → load → attach → consume → log)
  - 정상 종료 (SIGINT/SIGTERM), 필터/리소스 자동 정리
- **단위 테스트** — decode (IPv4/IPv6/VXLAN/VLAN), FormatIP, 잘린 데이터 에러 처리
- **실 환경 검증** — `tun0`에 tc/ingress 어태치 성공, VPN 클라이언트 트래픽 실시간 캡처 확인

**미구현 (TODO):**
- Phase 4: Event Transport (gRPC 클라이언트, 배칭, 백프레셔)
- Phase 5: 프로토콜 파서 (DNS, TLS SNI, HTTP Host)
- Phase 6: 하드닝 (BPF map 튜닝, drop 모니터링)

**설계 결정:**
- CO-RE 방식 (커널 버전 무관 단일 바이너리)
- L3/L2 자동 감지: `first_byte[7:4]` + `skb->protocol` 교차검증으로 tun(raw IP)과 Ethernet 모두 지원
- `parse_l3()`는 `ip_off`(IP 헤더 시작 오프셋)을 직접 받아 L3/L2 디바이스 공통 사용
- 인터페이스 우선순위: `vnet*` > `brvx*` > `cloudbr*` > `tun0`
- CloudStack VXLAN 토폴로지 반영: `vxlan* → brvx-* → vnet*`

### 3. CloudStack Collector (`agents/cloudstack-collector/`) — ❌ 미시작

디렉토리만 존재. CloudStack API 폴링 예정.

### 4. Central Engine (`engine/`) — ❌ 미시작

- `engine/api/` — REST/gRPC API (빈 디렉토리)
- `engine/correlator/` — 3계층 상관 분석 (빈 디렉토리)
- `engine/detector/` — 이상 탐지 규칙 (빈 디렉토리)

---

## 주요 기술 스택

- **Go 1.24** (에이전트 전체)
- **eBPF** (CO-RE, cilium/ebpf v0.21.0)
- **clang 18** (BPF 컴파일)
- **gRPC + Protobuf** (에이전트 ↔ 엔진 통신)
- **vishvananda/netlink** (tc qdisc/filter 관리)
- **YAML** (설정 파일)

## 핵심 설정 파일

- `configs/agents/ebpf-agent.yaml` — 인터페이스 프리픽스 설정
- `configs/agents/openvpn-exporter.yaml` — 필드 필터링 + kill 트리거
- `deployments/systemd/openvpn-session-agent.service` — systemd 배포

## 네트워크 토폴로지 메모

- CloudStack 노드: `vnet*`, `cloudbr*`, VXLAN 경로 `vxlan* → brvx-* → vnet*`
- eBPF 인터페이스 탐색에 `brvx` 프리픽스 포함 필수

---

## 작업 이력

### 2026-03-17
- 프로젝트 전체 맥락 조사 및 Claude.md 최초 작성
- **eBPF Phase 2 완료**: `flow.bpf.c` 패킷 파서 (Ethernet → IPv4/IPv6 → TCP/UDP 5-tuple)
- **eBPF Phase 3 완료**: Go userspace 전체 파이프라인
  - `internal/bpf/generate.go` + bpf2go 코드 생성
  - `internal/collector/loader.go` — BPF 로드, tc ingress 어태치, clsact qdisc
  - `internal/collector/consumer.go` — ringbuf 소비, 바이너리 디코딩
  - `internal/events/types.go` — FlowEvent 구조체 (C struct 패딩 정렬)
  - `cmd/ebpf-agent/main.go` — 전체 통합 (rlimit → load → attach → consume → log)
- Consumer 단위 테스트 추가 (`consumer_test.go`)
- 실 환경 검증: `tun0`에 tc/ingress BPF 어태치 성공 (1120B xlated, 703B JIT)
- README.md 전면 개편 (빌드/실행 방법, 설정, 디렉토리 구조, 로드맵 등)
- `IMPLEMENTATION.md` 신규 작성 (아키텍처, BPF 파싱 흐름, 구조체 레이아웃, 설계 결정 등)

### 2026-04-08
- **802.1Q VLAN 지원 추가**
  - `common.h`: `flow_event`에 `vlan_id` 필드 추가 (기존 2B 패딩 대체, 구조체 104B 유지)
  - `flow.bpf.c`: EtherType `0x8100`/`0x88A8` 감지 → TCI에서 12-bit VLAN ID 추출
  - `events/types.go`: Go `FlowEvent.VlanID` 필드 추가
  - `main.go`: VLAN/VXLAN+VLAN 전용 로그 포맷
  - `consumer_test.go`: `TestDecodeFlowEvent_VLAN` 테스트 추가
- **L3 디바이스(tun) 지원 추가**
  - `flow.bpf.c`: `first_byte[7:4]` + `skb->protocol` 교차검증으로 L3(raw IP) vs L2(Ethernet) 자동 감지
  - `parse_l3()` 리팩토링: `eth_off` → `ip_off` (IP 헤더 시작 오프셋 직접 전달)
  - tun0에서 Ethernet 헤더 없는 raw IP 패킷 정상 파싱 확인
- **실 환경 검증**: VPN 클라이언트(hocha/10.8.0.2) 트래픽 실시간 캡처 성공
- 전체 테스트 통과 (11/11)
- 문서 업데이트 (IMPLEMENTATION.md, README.md, Claude.md)

### 2026-03-18
- **VXLAN inner+outer 동시 파싱 구현**
  - `common.h`: `flow_event`에 `vni`, `outer_src_ip`, `outer_dst_ip` 필드 추가 (72B → 104B)
  - `flow.bpf.c`: L3 파서를 재사용 가능한 `parse_l3()` 함수로 리팩토링, `try_parse_vxlan()` 추가
    - UDP:4789 감지 시 VXLAN I-flag 확인 → VNI 24-bit 추출
    - inner Ethernet → inner IP → inner L4 재귀 파싱
    - outer IP는 `outer_src_ip`/`outer_dst_ip`에, inner IP는 기본 필드에 저장
  - `events/types.go`: Go `FlowEvent` 구조체에 `VNI`, `OuterSrcIP`, `OuterDstIP` 추가 (2B 패딩 조정)
  - `main.go`: VNI != 0이면 VXLAN 전용 로그 포맷 출력
  - `consumer_test.go`: VXLAN decode 테스트 추가 (`TestDecodeFlowEvent_VXLAN`)
  - BPF 프로그램: 2736B xlated, 1553B JIT (이전 1120B/703B에서 증가)
  - 전체 테스트 통과 (10/10), 실 환경 로드/어태치 성공

### 2026-03-12 (추정)
- OpenVPN Session Agent MVP 완료
- eBPF Agent 스켈레톤 부트스트랩 (config + interface discovery)
- 문서 정리 (README, architecture.md, requirements.md)

---

## 다음 작업 후보

1. **eBPF Phase 4** — gRPC Event Transport (엔진으로 FlowEvent 배치 전송)
2. **eBPF Phase 5** — 프로토콜 파서 (DNS, TLS SNI, HTTP Host)
3. **Central Engine API** — gRPC 서버 구현 (세션 스냅샷 수신)
4. **CloudStack Collector** — API 폴링 구현
