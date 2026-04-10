package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"ebpf-agent/internal/collector"

	"gopkg.in/yaml.v3"
)

const envConfigPath = "EBPF_AGENT_CONFIG_PATH"

var defaultConfigPathCandidates = []string{
	"configs/agents/ebpf-agent.yaml",
	"../../configs/agents/ebpf-agent.yaml",
	"/etc/openvpn-monitoring/ebpf-agent.yaml",
}

type agentConfig struct {
	Name string `yaml:"name"`
}

type interfacesConfig struct {
	IncludePrefixes []string `yaml:"include_prefixes"`
	ExcludePrefixes []string `yaml:"exclude_prefixes"`
	RequireUp       *bool    `yaml:"require_up"`
}

type runtimeConfig struct {
	Agent      agentConfig      `yaml:"agent"`
	Interfaces interfacesConfig `yaml:"interfaces"`
}

func resolveConfigPath() string {
	if v := strings.TrimSpace(os.Getenv(envConfigPath)); v != "" {
		return v
	}

	for _, path := range defaultConfigPathCandidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return defaultConfigPathCandidates[0]
}

func loadConfig(path string) (runtimeConfig, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return runtimeConfig{}, fmt.Errorf("read config %q: %w", path, err)
	}

	var cfg runtimeConfig
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return runtimeConfig{}, fmt.Errorf("parse config %q: %w", path, err)
	}

	if strings.TrimSpace(cfg.Agent.Name) == "" {
		cfg.Agent.Name = "ebpf-agent"
	}

	if len(cfg.Interfaces.IncludePrefixes) == 0 {
		cfg.Interfaces.IncludePrefixes = []string{"vnet", "cloudbr", "brvx", "tun", "vxlan"}
	}
	if len(cfg.Interfaces.ExcludePrefixes) == 0 {
		cfg.Interfaces.ExcludePrefixes = []string{"lo", "docker", "veth", "virbr", "cni", "flannel", "kube"}
	}
	if cfg.Interfaces.RequireUp == nil {
		v := true
		cfg.Interfaces.RequireUp = &v
	}

	return cfg, nil
}

func (c runtimeConfig) validate() error {
	if len(c.Interfaces.IncludePrefixes) == 0 {
		return errors.New("interfaces.include_prefixes must not be empty")
	}
	return nil
}

func (c runtimeConfig) toSelector() collector.InterfaceSelector {
	return collector.InterfaceSelector{
		IncludePrefixes: c.Interfaces.IncludePrefixes,
		ExcludePrefixes: c.Interfaces.ExcludePrefixes,
		RequireUp:       *c.Interfaces.RequireUp,
	}
}
