package collector_test

import (
	"net"
	"testing"

	"ebpf-agent/internal/collector"
	"ebpf-agent/internal/events"
)

// ── AggregatePerCPU ────────────────────────────────────────────────────

func TestAggregatePerCPU_basic(t *testing.T) {
	perCPU := []events.FlowMetrics{
		{Bytes: 1000, Packets: 5, FirstSeen: 100, LastSeen: 200},
		{Bytes: 2000, Packets: 10, FirstSeen: 150, LastSeen: 300},
		{Bytes: 0, Packets: 0, FirstSeen: 0, LastSeen: 0}, // idle CPU
	}

	got := collector.AggregatePerCPU(perCPU)

	if got.Bytes != 3000 {
		t.Errorf("Bytes = %d, want 3000", got.Bytes)
	}
	if got.Packets != 15 {
		t.Errorf("Packets = %d, want 15", got.Packets)
	}
	if got.FirstSeen != 100 {
		t.Errorf("FirstSeen = %d, want 100 (minimum non-zero)", got.FirstSeen)
	}
	if got.LastSeen != 300 {
		t.Errorf("LastSeen = %d, want 300 (maximum)", got.LastSeen)
	}
}

func TestAggregatePerCPU_single(t *testing.T) {
	perCPU := []events.FlowMetrics{
		{Bytes: 500, Packets: 3, FirstSeen: 50, LastSeen: 100},
	}
	got := collector.AggregatePerCPU(perCPU)
	if got.Bytes != 500 || got.Packets != 3 {
		t.Errorf("unexpected: bytes=%d packets=%d", got.Bytes, got.Packets)
	}
}

func TestAggregatePerCPU_allZero(t *testing.T) {
	perCPU := []events.FlowMetrics{{}, {}, {}}
	got := collector.AggregatePerCPU(perCPU)
	if got.Packets != 0 {
		t.Errorf("expected 0 packets, got %d", got.Packets)
	}
	// FirstSeen must remain 0 when all inputs are zero (not the zero-value min).
	if got.FirstSeen != 0 {
		t.Errorf("FirstSeen = %d, want 0 for all-zero input", got.FirstSeen)
	}
}

// ── FormatIP ───────────────────────────────────────────────────────────

func TestFormatIP_v4(t *testing.T) {
	var ip [16]byte
	copy(ip[:4], net.ParseIP("172.16.0.1").To4())
	got := collector.FormatIP(ip, 4)
	if got != "172.16.0.1" {
		t.Errorf("FormatIP = %q, want 172.16.0.1", got)
	}
}

func TestFormatIP_v6(t *testing.T) {
	var ip [16]byte
	copy(ip[:], net.ParseIP("::1").To16())
	got := collector.FormatIP(ip, 6)
	if got != "::1" {
		t.Errorf("FormatIP = %q, want ::1", got)
	}
}

// ── FormatFlow ─────────────────────────────────────────────────────────

func TestFormatFlow_IPv4TCP(t *testing.T) {
	var src, dst [16]byte
	copy(src[:4], net.ParseIP("10.8.0.2").To4())
	copy(dst[:4], net.ParseIP("8.8.8.8").To4())

	ev := events.FlowEvent{
		IPVersion: 4,
		Protocol:  6,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   54321,
		DstPort:   443,
		Bytes:     1500,
		Packets:   1,
		IfIndex:   3,
	}

	got := collector.FormatFlow(ev)
	want := "10.8.0.2:54321 → 8.8.8.8:443 proto=6 bytes=1500 pkts=1 if=3"
	if got != want {
		t.Errorf("FormatFlow =\n  %q\nwant\n  %q", got, want)
	}
}

func TestFormatFlow_IPv6UDP(t *testing.T) {
	var src, dst [16]byte
	copy(src[:], net.ParseIP("2001:db8::1").To16())
	copy(dst[:], net.ParseIP("2001:db8::2").To16())

	ev := events.FlowEvent{
		IPVersion: 6,
		Protocol:  17,
		SrcIP:     src,
		DstIP:     dst,
		SrcPort:   12345,
		DstPort:   53,
		Bytes:     200,
		Packets:   2,
		IfIndex:   5,
	}

	got := collector.FormatFlow(ev)
	want := "2001:db8::1:12345 → 2001:db8::2:53 proto=17 bytes=200 pkts=2 if=5"
	if got != want {
		t.Errorf("FormatFlow =\n  %q\nwant\n  %q", got, want)
	}
}
