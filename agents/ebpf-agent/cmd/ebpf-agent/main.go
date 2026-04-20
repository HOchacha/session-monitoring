package main

import (
	"context"
	"log"
	"os/signal"
	"syscall"
	"time"

	"ebpf-agent/internal/collector"

	"github.com/cilium/ebpf/rlimit"
)

const flowPollInterval = 5 * time.Second

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	configPath := resolveConfigPath()
	cfg, err := loadConfig(configPath)
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}
	if err := cfg.validate(); err != nil {
		log.Fatalf("invalid config %q: %v", configPath, err)
	}

	selector := cfg.toSelector()
	attachIfaces, err := collector.DiscoverAttachInterfaces(selector)
	if err != nil {
		log.Fatalf("failed to discover interfaces: %v", err)
	}

	log.Printf("%s starting (config=%s)", cfg.Agent.Name, configPath)
	log.Printf("attach candidates: %v", attachIfaces)

	if len(attachIfaces) == 0 {
		log.Fatalf("no interfaces matched — check include/exclude prefixes")
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	att, err := collector.LoadAndAttach(attachIfaces)
	if err != nil {
		log.Fatalf("load/attach BPF: %v", err)
	}
	defer att.Close()

	log.Printf("flow map consumer starting (poll=%s)", flowPollInterval)
	flowCh := collector.ReadFlows(ctx, att.FlowMap, flowPollInterval)

	for {
		select {
		case ev, ok := <-flowCh:
			if !ok {
				log.Printf("%s consumer channel closed", cfg.Agent.Name)
				return
			}
			log.Printf("flow: %s", collector.FormatFlow(ev))
		case <-ctx.Done():
			log.Printf("%s stopping", cfg.Agent.Name)
			for range flowCh {
			}
			return
		}
	}
}
