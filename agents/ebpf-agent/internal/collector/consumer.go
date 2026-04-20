package collector

import (
	"context"
	"fmt"
	"log"
	"net"
	"time"

	"ebpf-agent/internal/events"

	"github.com/cilium/ebpf"
)

// ReadFlows periodically iterates the per-CPU flow map, aggregates
// per-CPU counters, and emits FlowEvents on the returned channel.
// Entries are deleted after reading to reset counters for the next cycle.
func ReadFlows(ctx context.Context, flowMap *ebpf.Map, interval time.Duration) <-chan events.FlowEvent {
	ch := make(chan events.FlowEvent, 256)

	go func() {
		defer close(ch)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				drainFlowMap(flowMap, ch)
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch
}

// drainFlowMap iterates all entries in the per-CPU hash map, sums
// per-CPU metrics for each flow, emits the aggregated event, and
// deletes the entry to reset counters.
func drainFlowMap(flowMap *ebpf.Map, ch chan<- events.FlowEvent) {
	var key events.FlowKey
	var perCPU []events.FlowMetrics
	var toDelete []events.FlowKey

	iter := flowMap.Iterate()
	for iter.Next(&key, &perCPU) {
		total := AggregatePerCPU(perCPU)
		if total.Packets == 0 {
			continue
		}

		ev := events.FlowEvent{
			TSUnixNano: total.LastSeen,
			IfIndex:    key.IfIndex,
			IPVersion:  key.IPVersion,
			Protocol:   key.Protocol,
			SrcIP:      key.SrcIP,
			DstIP:      key.DstIP,
			SrcPort:    key.SrcPort,
			DstPort:    key.DstPort,
			Bytes:      total.Bytes,
			Packets:    total.Packets,
		}

		select {
		case ch <- ev:
		default:
			// Channel full — drop to avoid blocking the drain loop.
		}

		toDelete = append(toDelete, key)
	}

	if err := iter.Err(); err != nil {
		log.Printf("flow map iterate: %v", err)
	}

	for i := range toDelete {
		if err := flowMap.Delete(&toDelete[i]); err != nil {
			log.Printf("flow map delete: %v", err)
		}
	}
}

// AggregatePerCPU sums per-CPU FlowMetrics slices into a single FlowMetrics.
// Exported for testing.
func AggregatePerCPU(perCPU []events.FlowMetrics) events.FlowMetrics {
	var total events.FlowMetrics
	for _, v := range perCPU {
		total.Bytes += v.Bytes
		total.Packets += v.Packets
		if v.FirstSeen != 0 && (total.FirstSeen == 0 || v.FirstSeen < total.FirstSeen) {
			total.FirstSeen = v.FirstSeen
		}
		if v.LastSeen > total.LastSeen {
			total.LastSeen = v.LastSeen
		}
	}
	return total
}

// FormatIP returns the human-readable form of the IP stored in a [16]byte array.
func FormatIP(ip [16]byte, version uint8) string {
	if version == 4 {
		return net.IP(ip[:4]).String()
	}
	return net.IP(ip[:]).String()
}

// FormatFlow returns a one-line summary of a FlowEvent for logging.
func FormatFlow(ev events.FlowEvent) string {
	return fmt.Sprintf("%s:%d → %s:%d proto=%d bytes=%d pkts=%d if=%d",
		FormatIP(ev.SrcIP, ev.IPVersion), ev.SrcPort,
		FormatIP(ev.DstIP, ev.IPVersion), ev.DstPort,
		ev.Protocol, ev.Bytes, ev.Packets, ev.IfIndex)
}
