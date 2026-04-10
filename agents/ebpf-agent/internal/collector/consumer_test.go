package collector_test

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"

	"ebpf-agent/internal/collector"
	"ebpf-agent/internal/events"
)

func buildRawEvent(ev events.FlowEvent) []byte {
	var buf bytes.Buffer
	binary.Write(&buf, binary.LittleEndian, ev)
	return buf.Bytes()
}

func TestDecodeFlowEvent_IPv4TCP(t *testing.T) {
	src := net.ParseIP("10.8.0.6").To4()
	dst := net.ParseIP("192.168.1.1").To4()

	var srcArr, dstArr [16]byte
	copy(srcArr[:4], src)
	copy(dstArr[:4], dst)

	raw := buildRawEvent(events.FlowEvent{
		TSUnixNano: 1234567890,
		IfIndex:    3,
		IPVersion:  4,
		Protocol:   6, // TCP
		SrcIP:      srcArr,
		DstIP:      dstArr,
		SrcPort:    54321,
		DstPort:    443,
		Bytes:      1500,
		Packets:    1,
	})

	ev, err := collector.DecodeFlowEvent(raw)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if ev.IPVersion != 4 {
		t.Errorf("ip_version = %d, want 4", ev.IPVersion)
	}
	if ev.Protocol != 6 {
		t.Errorf("protocol = %d, want 6", ev.Protocol)
	}
	if ev.SrcPort != 54321 {
		t.Errorf("src_port = %d, want 54321", ev.SrcPort)
	}
	if ev.DstPort != 443 {
		t.Errorf("dst_port = %d, want 443", ev.DstPort)
	}
	if ev.Bytes != 1500 {
		t.Errorf("bytes = %d, want 1500", ev.Bytes)
	}
	if ev.Packets != 1 {
		t.Errorf("packets = %d, want 1", ev.Packets)
	}
	if ev.VNI != 0 {
		t.Errorf("vni = %d, want 0 for non-VXLAN", ev.VNI)
	}

	gotSrc := collector.FormatIP(ev.SrcIP, ev.IPVersion)
	if gotSrc != "10.8.0.6" {
		t.Errorf("src_ip = %q, want 10.8.0.6", gotSrc)
	}
	gotDst := collector.FormatIP(ev.DstIP, ev.IPVersion)
	if gotDst != "192.168.1.1" {
		t.Errorf("dst_ip = %q, want 192.168.1.1", gotDst)
	}
}

func TestDecodeFlowEvent_IPv6UDP(t *testing.T) {
	src := net.ParseIP("2001:db8::1")
	dst := net.ParseIP("2001:db8::2")

	var srcArr, dstArr [16]byte
	copy(srcArr[:], src.To16())
	copy(dstArr[:], dst.To16())

	raw := buildRawEvent(events.FlowEvent{
		TSUnixNano: 9999,
		IfIndex:    5,
		IPVersion:  6,
		Protocol:   17, // UDP
		SrcIP:      srcArr,
		DstIP:      dstArr,
		SrcPort:    12345,
		DstPort:    53,
		Bytes:      200,
		Packets:    1,
	})

	ev, err := collector.DecodeFlowEvent(raw)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if ev.IPVersion != 6 {
		t.Errorf("ip_version = %d, want 6", ev.IPVersion)
	}
	if ev.Protocol != 17 {
		t.Errorf("protocol = %d, want 17", ev.Protocol)
	}

	gotSrc := collector.FormatIP(ev.SrcIP, ev.IPVersion)
	if gotSrc != "2001:db8::1" {
		t.Errorf("src_ip = %q, want 2001:db8::1", gotSrc)
	}
	gotDst := collector.FormatIP(ev.DstIP, ev.IPVersion)
	if gotDst != "2001:db8::2" {
		t.Errorf("dst_ip = %q, want 2001:db8::2", gotDst)
	}
}

func TestDecodeFlowEvent_VXLAN(t *testing.T) {
	// Inner packet: VM 10.100.0.5 -> 10.200.0.1, TCP:8080
	var innerSrc, innerDst [16]byte
	copy(innerSrc[:4], net.ParseIP("10.100.0.5").To4())
	copy(innerDst[:4], net.ParseIP("10.200.0.1").To4())

	// Outer tunnel endpoints: 10.10.0.14 -> 10.10.0.15
	var outerSrc, outerDst [16]byte
	copy(outerSrc[:4], net.ParseIP("10.10.0.14").To4())
	copy(outerDst[:4], net.ParseIP("10.10.0.15").To4())

	raw := buildRawEvent(events.FlowEvent{
		TSUnixNano: 5555,
		IfIndex:    7,
		IPVersion:  4,
		Protocol:   6, // inner TCP
		SrcIP:      innerSrc,
		DstIP:      innerDst,
		SrcPort:    49000,
		DstPort:    8080,
		VNI:        5494,
		OuterSrcIP: outerSrc,
		OuterDstIP: outerDst,
		Bytes:      1400,
		Packets:    1,
	})

	ev, err := collector.DecodeFlowEvent(raw)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	// Inner fields
	if ev.VNI != 5494 {
		t.Errorf("vni = %d, want 5494", ev.VNI)
	}
	if ev.DstPort != 8080 {
		t.Errorf("inner dst_port = %d, want 8080", ev.DstPort)
	}
	if ev.Protocol != 6 {
		t.Errorf("inner protocol = %d, want 6", ev.Protocol)
	}

	gotInnerSrc := collector.FormatIP(ev.SrcIP, ev.IPVersion)
	if gotInnerSrc != "10.100.0.5" {
		t.Errorf("inner src = %q, want 10.100.0.5", gotInnerSrc)
	}
	gotInnerDst := collector.FormatIP(ev.DstIP, ev.IPVersion)
	if gotInnerDst != "10.200.0.1" {
		t.Errorf("inner dst = %q, want 10.200.0.1", gotInnerDst)
	}

	// Outer fields
	gotOuterSrc := collector.FormatIP(ev.OuterSrcIP, 4)
	if gotOuterSrc != "10.10.0.14" {
		t.Errorf("outer src = %q, want 10.10.0.14", gotOuterSrc)
	}
	gotOuterDst := collector.FormatIP(ev.OuterDstIP, 4)
	if gotOuterDst != "10.10.0.15" {
		t.Errorf("outer dst = %q, want 10.10.0.15", gotOuterDst)
	}
}

func TestDecodeFlowEvent_VLAN(t *testing.T) {
	src := net.ParseIP("192.168.10.1").To4()
	dst := net.ParseIP("192.168.10.2").To4()

	var srcArr, dstArr [16]byte
	copy(srcArr[:4], src)
	copy(dstArr[:4], dst)

	raw := buildRawEvent(events.FlowEvent{
		TSUnixNano: 7777,
		IfIndex:    2,
		IPVersion:  4,
		Protocol:   6, // TCP
		SrcIP:      srcArr,
		DstIP:      dstArr,
		SrcPort:    40000,
		DstPort:    443,
		VlanID:     100,
		Bytes:      800,
		Packets:    1,
	})

	ev, err := collector.DecodeFlowEvent(raw)
	if err != nil {
		t.Fatalf("decode error: %v", err)
	}

	if ev.VlanID != 100 {
		t.Errorf("vlan_id = %d, want 100", ev.VlanID)
	}
	if ev.VNI != 0 {
		t.Errorf("vni = %d, want 0 for non-VXLAN", ev.VNI)
	}
	if ev.Protocol != 6 {
		t.Errorf("protocol = %d, want 6", ev.Protocol)
	}
	gotSrc := collector.FormatIP(ev.SrcIP, ev.IPVersion)
	if gotSrc != "192.168.10.1" {
		t.Errorf("src_ip = %q, want 192.168.10.1", gotSrc)
	}
	gotDst := collector.FormatIP(ev.DstIP, ev.IPVersion)
	if gotDst != "192.168.10.2" {
		t.Errorf("dst_ip = %q, want 192.168.10.2", gotDst)
	}
}

func TestDecodeFlowEvent_TruncatedData(t *testing.T) {
	_, err := collector.DecodeFlowEvent([]byte{0x01, 0x02})
	if err == nil {
		t.Fatal("expected error on truncated data")
	}
}

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
