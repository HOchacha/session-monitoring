# OpenVPN Session Agent

OpenVPN Management Interface(`127.0.0.1:7505`)를 사용하는 Layer 2 수집/제어 에이전트.

이 바이너리는 현재 두 가지 동작 모드를 가진다.
- 수집 모드: `status 3` 주기 폴링 -> 세션 스냅샷 생성 -> gRPC 전송(또는 standalone 로그)
- 종료 모드: 특정 CN 세션 강제 종료 후 즉시 프로세스 종료(one-shot)

## 동작 정리

### 1) 수집 모드 (기본)
- OpenVPN Mgmt에 접속해 `status 3`를 읽음
- `CLIENT_LIST`를 파싱해 세션 목록/집계(bytes sum, active count) 생성
- `--export-config` YAML로 payload 필드 선택 적용
- `--log-payload=true`면 JSON payload 로그 출력
- gRPC 전송이 가능하면 전송, 실패 시 자동 standalone 폴백

### 2) 종료 모드 (Decision Engine 트리거용)
- `kill_common_name`가 export config(YAML)에 주어지면 수집 루프에 들어가지 않음
- 메시지 미지정: `kill <cn>` 수행
- 메시지 지정(`kill_common_name_message`): `status 3`로 `CN -> CID` 조회 후 `client-kill CID "message"` 수행
- 성공/실패 로그 출력 후 즉시 종료

## 빠른 시작

```bash
cd agents/openvpn-exporter
go mod tidy
go build -o bin/openvpn-session-agent ./cmd/session-agent
```

수집 + gRPC 전송:

```bash
./bin/openvpn-session-agent \
  --management-addr 127.0.0.1:7505 \
  --grpc-target 127.0.0.1:50051 \
  --grpc-method /openvpn.v1.SessionService/ReportSnapshot \
  --export-config ../../configs/agents/openvpn-exporter.yaml \
  --log-payload true \
  --interval 10s
```

standalone 수집:

```bash
./bin/openvpn-session-agent \
  --management-addr 127.0.0.1:7505 \
  --standalone \
  --interval 10s
```

## Decision Engine 연동 (권장)

외부 Decision Engine이 위반 판단 시, exporter를 one-shot 실행해서 세션을 종료한다.

### 메시지 없이 종료

Decision Engine이 export config에 아래 값을 기록:

```yaml
kill_common_name: "alice"
kill_common_name_message: ""
```

실행:

```bash
./bin/openvpn-session-agent \
  --management-addr 127.0.0.1:7505 \
  --timeout 5s \
  --export-config ../../configs/agents/openvpn-exporter.yaml
```

### 메시지 포함 종료

Decision Engine이 export config에 아래 값을 기록:

```yaml
kill_common_name: "alice"
kill_common_name_message: "SOLID Cloud 사용자 약관 위반으로 사용자 계정이 정지되었습니다."
```

실행:

```bash
./bin/openvpn-session-agent \
  --management-addr 127.0.0.1:7505 \
  --timeout 5s \
  --export-config ../../configs/agents/openvpn-exporter.yaml
```

주의:
- 클라이언트 메시지 노출 형태는 OpenVPN 클라이언트 UI/로그 구현에 따라 다를 수 있다.

## 설정 값

플래그/환경변수:
- `--management-addr` / `OVPN_MGMT_ADDR` (default: `127.0.0.1:7505`)
- `--grpc-target` / `ENGINE_GRPC_TARGET` (default: `127.0.0.1:50051`)
- `--grpc-method` / `ENGINE_GRPC_METHOD` (default: `/openvpn.v1.SessionService/ReportSnapshot`)
- `--interval` / `COLLECT_INTERVAL` (default: `10s`)
- `--timeout` / `DIAL_TIMEOUT` (default: `5s`)
- `--standalone` / `STANDALONE_MODE` (default: `false`)
- `--log-payload` / `LOG_SNAPSHOT_PAYLOAD` (default: `true`)
- `--export-config` / `EXPORT_CONFIG_PATH` (default: empty)

종료 모드 설정은 YAML config의 아래 필드를 사용한다.
- `kill_common_name`
- `kill_common_name_message`

## Export YAML

`configs/agents/openvpn-exporter.yaml` 예시:

```yaml
snapshot_fields:
  - collected_at
  - active_client_count
  - bytes_received_sum
  - bytes_sent_sum
  - sessions

session_fields:
  - common_name
  - virtual_address
  - bytes_received
  - bytes_sent

kill_common_name: ""
kill_common_name_message: ""
```

규칙:
- `snapshot_fields` 비어 있으면 상위 payload 전체 유지
- `session_fields` 비어 있으면 `sessions[]` 내부 필드 전체 유지

## 전송 payload 형식

gRPC 요청은 `google.protobuf.Struct` 기반이며, 기본적으로 아래 형태를 가진다.

```json
{
  "collected_at": "2026-03-11T05:10:00Z",
  "server_time": "2026-03-11 05:01:00",
  "server_time_unix": 1773205260,
  "active_client_count": 1,
  "bytes_received_sum": 1024,
  "bytes_sent_sum": 4096,
  "sessions": [
    {
      "common_name": "alice",
      "real_address": "203.0.113.10:54000",
      "virtual_address": "10.8.0.6",
      "bytes_received": 512,
      "bytes_sent": 256,
      "connected_since": "2026-03-11 05:00:00",
      "client_id": "1",
      "peer_id": "2",
      "cipher": "AES-256-GCM"
    }
  ],
  "collector_source": "openvpn-management-interface",
  "collector_status_type": "status_3"
}
```
