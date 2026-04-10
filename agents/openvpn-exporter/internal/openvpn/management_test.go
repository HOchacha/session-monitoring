package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func TestReadStatusV3(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte(">INFO:OpenVPN Management Interface Version 5 -- type 'help' for more info\n"))

		r := bufio.NewReader(conn)
		// Read only the status command; quit arrives after END is sent.
		_, _ = r.ReadString('\n')

		resp := strings.Join([]string{
			"TITLE\tOpenVPN 2.6.19",
			"TIME\t2026-03-11 05:01:00\t1773205260",
			">STATE:1773205260,CONNECTED,SUCCESS,10.8.0.1,203.0.113.1",
			"CLIENT_LIST\talice\t203.0.113.10:50000\t10.8.0.6\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t1\t2\tAES-256-GCM",
			"END",
		}, "\n") + "\n"
		_, _ = conn.Write([]byte(resp))
	}()

	c := &Client{Address: ln.Addr().String(), Timeout: 2 * time.Second}
	lines, err := c.ReadStatusV3()
	if err != nil {
		t.Fatalf("ReadStatusV3 failed: %v", err)
	}

	if len(lines) < 3 {
		t.Fatalf("expected at least 3 lines, got %d", len(lines))
	}
	if strings.HasPrefix(lines[0], ">") {
		t.Fatalf("expected async lines to be filtered out")
	}

	<-done
}

func TestKillByCommonName(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("Management Interface for OpenVPN\n"))

		r := bufio.NewReader(conn)
		cmd, _ := r.ReadString('\n')
		if strings.TrimSpace(cmd) != "kill alice" {
			_, _ = conn.Write([]byte("ERROR: bad command\n"))
			return
		}
		_, _ = conn.Write([]byte("SUCCESS: client-kill command succeeded\n"))
	}()

	c := &Client{Address: ln.Addr().String(), Timeout: 2 * time.Second}
	if err := c.KillByCommonName("alice"); err != nil {
		t.Fatalf("KillByCommonName failed: %v", err)
	}

	<-done
}

func TestKillByCommonName_Error(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("Management Interface for OpenVPN\n"))

		r := bufio.NewReader(conn)
		_, _ = r.ReadString('\n')
		_, _ = conn.Write([]byte("ERROR: no such client\n"))
	}()

	c := &Client{Address: ln.Addr().String(), Timeout: 2 * time.Second}
	err = c.KillByCommonName("alice")
	if err == nil {
		t.Fatal("expected kill error")
	}

	<-done
}

func TestKillByCommonName_RejectWhitespace(t *testing.T) {
	c := &Client{Address: "127.0.0.1:7505", Timeout: time.Second}
	err := c.KillByCommonName("alice smith")
	if err == nil {
		t.Fatal("expected validation error")
	}
}

func TestClientIDsByCommonName(t *testing.T) {
	lines := []string{
		"TITLE\tOpenVPN 2.6.19",
		"CLIENT_LIST\talice\t203.0.113.10:50000\t10.8.0.6\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t1\t2\tAES-256-GCM",
		"CLIENT_LIST\tbob\t198.51.100.8:50001\t10.8.0.7\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t9\t2\tAES-256-GCM",
		"CLIENT_LIST\talice\t203.0.113.11:50002\t10.8.0.8\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t11\t2\tAES-256-GCM",
	}

	ids := clientIDsByCommonName(lines, "alice")
	if len(ids) != 2 {
		t.Fatalf("expected 2 ids, got %d", len(ids))
	}
	if ids[0] != "1" || ids[1] != "11" {
		t.Fatalf("unexpected ids: %#v", ids)
	}
}

func TestKillByCommonNameWithMessage(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	defer ln.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)

		// 1) status query connection
		conn1, err := ln.Accept()
		if err != nil {
			return
		}
		_, _ = conn1.Write([]byte("Management Interface for OpenVPN\n"))
		r1 := bufio.NewReader(conn1)
		_, _ = r1.ReadString('\n')
		resp := strings.Join([]string{
			"TITLE\tOpenVPN 2.6.19",
			"CLIENT_LIST\talice\t203.0.113.10:50000\t10.8.0.6\t\t1000\t2000\t2026-03-11 05:00:00\t1773205200\t\t3\t0\tAES-256-GCM",
			"END",
		}, "\n") + "\n"
		_, _ = conn1.Write([]byte(resp))
		_ = conn1.Close()

		// 2) client-kill connection
		conn2, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn2.Close()
		_, _ = conn2.Write([]byte("Management Interface for OpenVPN\n"))
		r2 := bufio.NewReader(conn2)
		cmd, _ := r2.ReadString('\n')
		got := strings.TrimSpace(cmd)
		want := "client-kill 3 \"SOLID Cloud 사용자 약관 위반으로 사용자 계정이 정지되었습니다.\""
		if got != want {
			_, _ = conn2.Write([]byte("ERROR: bad command\n"))
			return
		}
		_, _ = conn2.Write([]byte("SUCCESS: client-kill command succeeded\n"))
	}()

	c := &Client{Address: ln.Addr().String(), Timeout: 2 * time.Second}
	err = c.KillByCommonNameWithMessage("alice", "SOLID Cloud 사용자 약관 위반으로 사용자 계정이 정지되었습니다.")
	if err != nil {
		t.Fatalf("KillByCommonNameWithMessage failed: %v", err)
	}

	<-done
}

// TestReadStatusV3_Live connects to a real OpenVPN Management Interface at
// 127.0.0.1:7505.  The test is skipped automatically when the port is not
// reachable so it is safe to run in CI without an OpenVPN instance.
func TestReadStatusV3_Live(t *testing.T) {
	const addr = "127.0.0.1:7505"

	// Probe: skip if nothing is listening.
	probe, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("skipping live test: %s not reachable (%v)", addr, err)
	}
	probe.Close()

	c := &Client{Address: addr, Timeout: 5 * time.Second}
	lines, err := c.ReadStatusV3()
	if err != nil {
		if strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "i/o timeout") {
			t.Skipf("skipping live test: management interface not responding in time (%v)", err)
		}
		t.Fatalf("ReadStatusV3 failed: %v", err)
	}

	t.Logf("received %d lines from Management Interface", len(lines))
	for _, l := range lines {
		t.Log(l)
	}

	// Basic sanity: response must contain at least TITLE and GLOBAL_STATS lines.
	hasTitle := false
	hasGlobalStats := false
	for _, l := range lines {
		if strings.HasPrefix(l, "TITLE") {
			hasTitle = true
		}
		if strings.HasPrefix(l, "GLOBAL_STATS") {
			hasGlobalStats = true
		}
	}
	if !hasTitle {
		t.Error("expected a TITLE line in status response")
	}
	if !hasGlobalStats {
		t.Error("expected a GLOBAL_STATS line in status response")
	}
}

// TestKillByCommonName_Live_NonExistent validates that the kill command path
// works against a real management interface without impacting real users.
// It uses an intentionally non-existent CN and expects a management error.
func TestKillByCommonName_Live_NonExistent(t *testing.T) {
	const addr = "127.0.0.1:7505"

	probe, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("skipping live test: %s not reachable (%v)", addr, err)
	}
	probe.Close()

	cn := fmt.Sprintf("__integration_test_cn_%d__", time.Now().UnixNano())
	c := &Client{Address: addr, Timeout: 5 * time.Second}
	err = c.KillByCommonName(cn)
	if err == nil {
		t.Fatalf("expected management error for non-existent cn=%s", cn)
	}

	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "error:") && !strings.Contains(msg, "no such") && !strings.Contains(msg, "not found") {
		t.Fatalf("unexpected kill response error: %v", err)
	}
}

// TestKillByCommonName_Live_Existing performs a real kill for an existing CN.
// This test is destructive and therefore opt-in only.
//
// Run example:
// OPENVPN_LIVE_EXISTING_CN=alice go test ./internal/openvpn -run TestKillByCommonName_Live_Existing -v
func TestKillByCommonName_Live_Existing(t *testing.T) {
	const addr = "127.0.0.1:7505"

	cn := strings.TrimSpace(os.Getenv("OPENVPN_LIVE_EXISTING_CN"))
	if cn == "" {
		t.Skip("skipping live existing-cn kill test: OPENVPN_LIVE_EXISTING_CN is not set")
	}

	probe, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("skipping live test: %s not reachable (%v)", addr, err)
	}
	probe.Close()

	c := &Client{Address: addr, Timeout: 5 * time.Second}
	if err := c.KillByCommonName(cn); err != nil {
		t.Fatalf("expected kill success for cn=%s, got error: %v", cn, err)
	}

	t.Logf("killed client(s) with cn=%s", cn)
}

func TestKillByCommonNameWithMessage_Live_Existing(t *testing.T) {
	const addr = "127.0.0.1:7505"

	cn := strings.TrimSpace(os.Getenv("OPENVPN_LIVE_EXISTING_CN"))
	if cn == "" {
		t.Skip("skipping live existing-cn kill-with-message test: OPENVPN_LIVE_EXISTING_CN is not set")
	}

	msg := strings.TrimSpace(os.Getenv("OPENVPN_LIVE_EXISTING_CN_MESSAGE"))
	if msg == "" {
		msg = "DISCONNECT_BY_ADMIN"
	}

	probe, err := net.DialTimeout("tcp", addr, 1*time.Second)
	if err != nil {
		t.Skipf("skipping live test: %s not reachable (%v)", addr, err)
	}
	probe.Close()

	c := &Client{Address: addr, Timeout: 5 * time.Second}
	if err := c.KillByCommonNameWithMessage(cn, msg); err != nil {
		t.Fatalf("expected kill-with-message success for cn=%s, got error: %v", cn, err)
	}

	t.Logf("killed client(s) with cn=%s message=%q", cn, msg)
}
