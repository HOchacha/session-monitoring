package main

import (
	"context"
	"fmt"
	"ebpf-agent/internal/collector"
	"log"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf/rlimit"
)

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

	// Remove memlock rlimit for kernels < 5.11.
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	att, err := collector.LoadAndAttach(attachIfaces)
	if err != nil {
		log.Fatalf("load/attach BPF: %v", err)
	}
	defer att.Close()

	log.Printf("ringbuf consumer starting")
	events := collector.ConsumeEvents(ctx, att.Reader)

	for {
		select {
		case ev, ok := <-events:
			if !ok {
				log.Printf("%s consumer channel closed", cfg.Agent.Name)
				return
			}
			vlanTag := ""
			if ev.VlanID != 0 {
				vlanTag = fmt.Sprintf(" vlan=%d", ev.VlanID)
			}
			if ev.VNI != 0 {
				log.Printf("flow [vxlan vni=%d%s outer=%s→%s]: %s:%d → %s:%d proto=%d bytes=%d if=%d",
					ev.VNI, vlanTag,
					collector.FormatIP(ev.OuterSrcIP, 4), collector.FormatIP(ev.OuterDstIP, 4),
					collector.FormatIP(ev.SrcIP, ev.IPVersion), ev.SrcPort,
					collector.FormatIP(ev.DstIP, ev.IPVersion), ev.DstPort,
					ev.Protocol, ev.Bytes, ev.IfIndex)
			} else if ev.VlanID != 0 {
				log.Printf("flow [vlan=%d]: %s:%d → %s:%d proto=%d bytes=%d if=%d",
					ev.VlanID,
					collector.FormatIP(ev.SrcIP, ev.IPVersion), ev.SrcPort,
					collector.FormatIP(ev.DstIP, ev.IPVersion), ev.DstPort,
					ev.Protocol, ev.Bytes, ev.IfIndex)
			} else {
				log.Printf("flow: %s:%d → %s:%d proto=%d bytes=%d if=%d",
					collector.FormatIP(ev.SrcIP, ev.IPVersion), ev.SrcPort,
					collector.FormatIP(ev.DstIP, ev.IPVersion), ev.DstPort,
					ev.Protocol, ev.Bytes, ev.IfIndex)
			}
		case <-ctx.Done():
			log.Printf("%s stopping", cfg.Agent.Name)
			att.Reader.Close()
			// Drain remaining events.
			for range events {
			}
			time.Sleep(50 * time.Millisecond)
			return
		}
	}
}
