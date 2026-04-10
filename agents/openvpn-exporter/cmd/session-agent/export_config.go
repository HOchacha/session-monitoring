package main

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type ExportConfig struct {
	SnapshotFields        []string `yaml:"snapshot_fields"`
	SessionFields         []string `yaml:"session_fields"`
	KillCommonName        string   `yaml:"kill_common_name"`
	KillCommonNameMessage string   `yaml:"kill_common_name_message"`
}

func loadExportConfig(path string) (*ExportConfig, error) {
	if strings.TrimSpace(path) == "" {
		return &ExportConfig{}, nil
	}

	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read export config: %w", err)
	}

	cfg := &ExportConfig{}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return nil, fmt.Errorf("parse export config yaml: %w", err)
	}
	cfg.KillCommonName = strings.TrimSpace(cfg.KillCommonName)
	cfg.KillCommonNameMessage = strings.TrimSpace(cfg.KillCommonNameMessage)
	return cfg, nil
}

func applyExportConfig(payload map[string]any, cfg *ExportConfig) map[string]any {
	if cfg == nil {
		return payload
	}

	filtered := payload
	if len(cfg.SnapshotFields) > 0 {
		allowed := sliceToSet(cfg.SnapshotFields)
		filtered = make(map[string]any, len(payload))
		for k, v := range payload {
			if _, ok := allowed[k]; ok {
				filtered[k] = v
			}
		}
	}

	sessionsRaw, ok := filtered["sessions"]
	if !ok || len(cfg.SessionFields) == 0 {
		return filtered
	}

	sessions, ok := sessionsRaw.([]any)
	if !ok {
		return filtered
	}

	sessionAllowed := sliceToSet(cfg.SessionFields)
	outSessions := make([]any, 0, len(sessions))
	for _, row := range sessions {
		m, ok := row.(map[string]any)
		if !ok {
			continue
		}
		out := make(map[string]any, len(m))
		for k, v := range m {
			if _, keep := sessionAllowed[k]; keep {
				out[k] = v
			}
		}
		outSessions = append(outSessions, out)
	}
	filtered["sessions"] = outSessions

	return filtered
}

func sliceToSet(in []string) map[string]struct{} {
	out := make(map[string]struct{}, len(in))
	for _, s := range in {
		key := strings.TrimSpace(s)
		if key == "" {
			continue
		}
		out[key] = struct{}{}
	}
	return out
}
