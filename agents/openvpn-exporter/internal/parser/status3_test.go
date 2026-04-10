package parser

import "testing"

func TestParseStatus_TabSeparated(t *testing.T) {
	lines := []string{
		"TITLE\tOpenVPN 2.6.19",
		"TIME\t2026-03-11 05:01:00\t1773205260",
		"CLIENT_LIST\talice\t203.0.113.10:50000\t10.8.0.6\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t1\t2\tAES-256-GCM",
		"CLIENT_LIST\tbob\t198.51.100.8:50123\t10.8.0.7\t\t3000\t4000\t2026-03-11 05:00:10\t1773205210\t\t3\t4\tCHACHA20-POLY1305",
	}

	snap := ParseStatus(lines)

	if snap.ActiveClientCount != 2 {
		t.Fatalf("expected 2 clients, got %d", snap.ActiveClientCount)
	}
	if snap.ServerTimeUnix != 1773205260 {
		t.Fatalf("unexpected server time unix: %d", snap.ServerTimeUnix)
	}
	if snap.BytesReceivedSum != 4000 {
		t.Fatalf("expected bytes received sum 4000, got %d", snap.BytesReceivedSum)
	}
	if snap.BytesSentSum != 6000 {
		t.Fatalf("expected bytes sent sum 6000, got %d", snap.BytesSentSum)
	}

	if snap.Sessions[0].CommonName != "alice" || snap.Sessions[0].VirtualAddress != "10.8.0.6" {
		t.Fatalf("unexpected first session: %+v", snap.Sessions[0])
	}
	if snap.Sessions[1].ClientID != "3" || snap.Sessions[1].PeerID != "4" {
		t.Fatalf("unexpected second session ids: %+v", snap.Sessions[1])
	}
}

func TestSplitStatusFields_CSV(t *testing.T) {
	line := "CLIENT_LIST,alice,203.0.113.10:50000,10.8.0.6,,1000,2000"
	parts := splitStatusFields(line)
	if len(parts) != 7 {
		t.Fatalf("expected 7 fields, got %d", len(parts))
	}
	if parts[4] != "" {
		t.Fatalf("expected empty virtual ipv6 field to be preserved")
	}
}
