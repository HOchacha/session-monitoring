package openvpn

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	Address string
	Timeout time.Duration
}

func (c *Client) ReadStatusV3() ([]string, error) {
	conn, err := net.DialTimeout("tcp", c.Address, c.Timeout)
	if err != nil {
		return nil, fmt.Errorf("connect management interface: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return nil, fmt.Errorf("set deadline: %w", err)
	}

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	// Consume banner/info line if available.
	_, _ = r.ReadString('\n')

	// Send only the status command first. Sending quit together causes
	// the server to close the connection before flushing the full response.
	if _, err := w.WriteString("status 3\n"); err != nil {
		return nil, fmt.Errorf("write status command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return nil, fmt.Errorf("flush management commands: %w", err)
	}

	lines := make([]string, 0, 128)
	for {
		line, err := r.ReadString('\n')
		if err != nil {
			break
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "END" {
			break
		}
		if strings.HasPrefix(line, ">") {
			continue
		}
		lines = append(lines, line)
	}

	// Gracefully close the session after reading the response.
	_, _ = w.WriteString("quit\n")
	_ = w.Flush()

	if len(lines) == 0 {
		return nil, fmt.Errorf("empty status response")
	}
	return lines, nil
}

func (c *Client) KillByCommonName(commonName string) error {
	return c.KillByCommonNameWithMessage(commonName, "")
}

func (c *Client) KillByCommonNameWithMessage(commonName, message string) error {
	cn := strings.TrimSpace(commonName)
	if cn == "" {
		return fmt.Errorf("common name is required")
	}
	if strings.ContainsAny(cn, " \t\r\n") {
		return fmt.Errorf("common name must not contain whitespace")
	}
	msg := strings.TrimSpace(message)
	if msg == "" {
		return c.killByCommonName(cn)
	}

	lines, err := c.ReadStatusV3()
	if err != nil {
		return fmt.Errorf("read status before client-kill: %w", err)
	}

	ids := clientIDsByCommonName(lines, cn)
	if len(ids) == 0 {
		return fmt.Errorf("no active client found for common name %q", cn)
	}

	for _, id := range ids {
		if err := c.killByClientID(id, msg); err != nil {
			return fmt.Errorf("kill client id %s for common name %q: %w", id, cn, err)
		}
	}
	return nil
}

func (c *Client) killByCommonName(cn string) error {

	conn, err := net.DialTimeout("tcp", c.Address, c.Timeout)
	if err != nil {
		return fmt.Errorf("connect management interface: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	_, _ = r.ReadString('\n')

	if _, err := w.WriteString(fmt.Sprintf("kill %s\n", cn)); err != nil {
		return fmt.Errorf("write kill command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush kill command: %w", err)
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read kill response: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") {
			continue
		}

		_, _ = w.WriteString("quit\n")
		_ = w.Flush()

		if strings.HasPrefix(line, "SUCCESS:") {
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			return fmt.Errorf("kill common name %q failed: %s", cn, line)
		}
		return fmt.Errorf("unexpected kill response: %s", line)
	}
}

func (c *Client) killByClientID(clientID, message string) error {
	id := strings.TrimSpace(clientID)
	if id == "" {
		return fmt.Errorf("client id is required")
	}

	conn, err := net.DialTimeout("tcp", c.Address, c.Timeout)
	if err != nil {
		return fmt.Errorf("connect management interface: %w", err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(c.Timeout)); err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	r := bufio.NewReader(conn)
	w := bufio.NewWriter(conn)

	_, _ = r.ReadString('\n')

	cmd := fmt.Sprintf("client-kill %s %s\n", id, strconv.Quote(message))
	if _, err := w.WriteString(cmd); err != nil {
		return fmt.Errorf("write client-kill command: %w", err)
	}
	if err := w.Flush(); err != nil {
		return fmt.Errorf("flush client-kill command: %w", err)
	}

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return fmt.Errorf("read client-kill response: %w", err)
		}
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, ">") {
			continue
		}

		_, _ = w.WriteString("quit\n")
		_ = w.Flush()

		if strings.HasPrefix(line, "SUCCESS:") {
			return nil
		}
		if strings.HasPrefix(line, "ERROR:") {
			return fmt.Errorf("%s", line)
		}
		return fmt.Errorf("unexpected client-kill response: %s", line)
	}
}

func clientIDsByCommonName(lines []string, commonName string) []string {
	ids := make([]string, 0, 2)
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		fields := splitManagementFields(line)
		if len(fields) < 11 || fields[0] != "CLIENT_LIST" {
			continue
		}
		if fields[1] == commonName && fields[10] != "" {
			ids = append(ids, fields[10])
		}
	}
	return ids
}

func splitManagementFields(line string) []string {
	if strings.Contains(line, "\t") {
		parts := strings.Split(line, "\t")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	if strings.Contains(line, ",") {
		parts := strings.Split(line, ",")
		for i := range parts {
			parts[i] = strings.TrimSpace(parts[i])
		}
		return parts
	}
	return strings.Fields(line)
}
