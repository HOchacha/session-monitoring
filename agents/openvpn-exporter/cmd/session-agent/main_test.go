package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"openvpn-session-agent/internal/parser"
)

func TestSessionsToAny(t *testing.T) {
	in := []parser.Session{
		{
			CommonName:     "alice",
			RealAddress:    "203.0.113.10:50000",
			VirtualAddress: "10.8.0.6",
			BytesReceived:  100,
			BytesSent:      200,
		},
	}

	out := sessionsToAny(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 element, got %d", len(out))
	}

	m, ok := out[0].(map[string]any)
	if !ok {
		t.Fatalf("expected map element")
	}
	if m["common_name"] != "alice" {
		t.Fatalf("unexpected common_name: %v", m["common_name"])
	}
	if m["virtual_address"] != "10.8.0.6" {
		t.Fatalf("unexpected virtual_address: %v", m["virtual_address"])
	}
}

func TestGetEnvDurationFallback(t *testing.T) {
	fallback := 7 * time.Second
	d := getEnvDuration("THIS_ENV_SHOULD_NOT_EXIST", fallback)
	if d != fallback {
		t.Fatalf("expected fallback duration %s, got %s", fallback, d)
	}
}

func TestGetEnvBool(t *testing.T) {
	const key = "OPENVPN_AGENT_TEST_BOOL"
	t.Setenv(key, "true")
	if !getEnvBool(key, false) {
		t.Fatalf("expected true from env")
	}

	t.Setenv(key, "not-a-bool")
	if !getEnvBool(key, true) {
		t.Fatalf("expected fallback true on parse error")
	}

	_ = os.Unsetenv(key)
	if getEnvBool(key, false) {
		t.Fatalf("expected fallback false when env missing")
	}
}

func TestPayloadToJSON(t *testing.T) {
	jsonText := payloadToJSON(map[string]any{"active_client_count": 2, "collector_source": "openvpn-management-interface"})
	if !strings.Contains(jsonText, "\"active_client_count\":2") {
		t.Fatalf("unexpected json: %s", jsonText)
	}

	bad := payloadToJSON(map[string]any{"bad": make(chan int)})
	if bad != "{\"error\":\"failed to marshal payload\"}" {
		t.Fatalf("unexpected fallback json: %s", bad)
	}
}

func TestLoadExportConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "export.yaml")
	err := os.WriteFile(path, []byte("snapshot_fields:\n  - collected_at\n  - sessions\nsession_fields:\n  - common_name\nkill_common_name: alice\nkill_common_name_message: policy_violation\n"), 0644)
	if err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := loadExportConfig(path)
	if err != nil {
		t.Fatalf("load export config: %v", err)
	}
	if len(cfg.SnapshotFields) != 2 || len(cfg.SessionFields) != 1 {
		t.Fatalf("unexpected config fields: %+v", cfg)
	}
	if cfg.KillCommonName != "alice" || cfg.KillCommonNameMessage != "policy_violation" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestApplyExportConfig(t *testing.T) {
	payload := map[string]any{
		"collected_at":        "2026-03-12T00:00:00Z",
		"active_client_count": 1,
		"bytes_received_sum":  100,
		"sessions": []any{
			map[string]any{
				"common_name":     "alice",
				"virtual_address": "10.8.0.6",
				"bytes_received":  uint64(100),
			},
		},
	}

	cfg := &ExportConfig{
		SnapshotFields: []string{"collected_at", "sessions"},
		SessionFields:  []string{"common_name", "virtual_address"},
	}

	filtered := applyExportConfig(payload, cfg)
	if _, ok := filtered["active_client_count"]; ok {
		t.Fatalf("active_client_count should be filtered out")
	}

	sessions, ok := filtered["sessions"].([]any)
	if !ok || len(sessions) != 1 {
		t.Fatalf("unexpected sessions: %#v", filtered["sessions"])
	}
	m, ok := sessions[0].(map[string]any)
	if !ok {
		t.Fatalf("unexpected session row type: %#v", sessions[0])
	}
	if _, ok := m["bytes_received"]; ok {
		t.Fatalf("bytes_received should be filtered out")
	}
	if m["common_name"] != "alice" || m["virtual_address"] != "10.8.0.6" {
		t.Fatalf("unexpected session data: %#v", m)
	}
}
