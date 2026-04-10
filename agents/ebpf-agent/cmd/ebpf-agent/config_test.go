package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveConfigPath_UsesEnvOverride(t *testing.T) {
	t.Setenv(envConfigPath, "/tmp/custom-ebpf-agent.yaml")
	got := resolveConfigPath()
	if got != "/tmp/custom-ebpf-agent.yaml" {
		t.Fatalf("expected env override path, got %q", got)
	}
}

func TestLoadConfig_AppliesDefaults(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "ebpf-agent.yaml")
	content := []byte("agent:\n  name: test-ebpf\ninterfaces: {}\n")
	if err := os.WriteFile(path, content, 0o644); err != nil {
		t.Fatalf("write test config: %v", err)
	}

	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("loadConfig failed: %v", err)
	}
	if cfg.Agent.Name != "test-ebpf" {
		t.Fatalf("unexpected agent name: %q", cfg.Agent.Name)
	}
	if len(cfg.Interfaces.IncludePrefixes) == 0 {
		t.Fatal("expected default include prefixes")
	}
	if cfg.Interfaces.RequireUp == nil || !*cfg.Interfaces.RequireUp {
		t.Fatal("expected default require_up=true")
	}
}
