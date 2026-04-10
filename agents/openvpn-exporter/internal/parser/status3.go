package parser

import (
	"strconv"
	"strings"
	"time"
)

type Session struct {
	CommonName     string `json:"common_name"`
	RealAddress    string `json:"real_address"`
	VirtualAddress string `json:"virtual_address"`
	BytesReceived  uint64 `json:"bytes_received"`
	BytesSent      uint64 `json:"bytes_sent"`
	ConnectedSince string `json:"connected_since"`
	ClientID       string `json:"client_id"`
	PeerID         string `json:"peer_id"`
	Cipher         string `json:"cipher"`
}

type Snapshot struct {
	CollectedAt       time.Time `json:"collected_at"`
	ServerTime        string    `json:"server_time,omitempty"`
	ServerTimeUnix    int64     `json:"server_time_unix,omitempty"`
	ActiveClientCount int       `json:"active_client_count"`
	BytesReceivedSum  uint64    `json:"bytes_received_sum"`
	BytesSentSum      uint64    `json:"bytes_sent_sum"`
	Sessions          []Session `json:"sessions"`
}

func ParseStatus(lines []string) Snapshot {
	s := Snapshot{CollectedAt: time.Now().UTC()}

	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}

		fields := splitStatusFields(line)
		if len(fields) == 0 {
			continue
		}

		switch fields[0] {
		case "TIME":
			if len(fields) >= 2 {
				s.ServerTime = fields[1]
			}
			if len(fields) >= 3 {
				ts, _ := strconv.ParseInt(fields[2], 10, 64)
				s.ServerTimeUnix = ts
			}
		case "CLIENT_LIST":
			cli := parseClientList(fields)
			if cli.CommonName == "" {
				continue
			}
			s.Sessions = append(s.Sessions, cli)
			s.BytesReceivedSum += cli.BytesReceived
			s.BytesSentSum += cli.BytesSent
		}
	}

	s.ActiveClientCount = len(s.Sessions)
	return s
}

func parseClientList(fields []string) Session {
	get := func(i int) string {
		if i >= 0 && i < len(fields) {
			return fields[i]
		}
		return ""
	}

	// status-version 2/3 client-list column indexes:
	// 0=CLIENT_LIST, 1=CN, 2=Real, 3=Virtual, 4=VirtualIPv6,
	// 5=BytesRx, 6=BytesTx, 7=ConnectedSince, 8=ConnectedSince(time_t),
	// 9=Username, 10=ClientID, 11=PeerID, 12=Cipher.
	bytesRx, _ := strconv.ParseUint(get(5), 10, 64)
	bytesTx, _ := strconv.ParseUint(get(6), 10, 64)

	return Session{
		CommonName:     get(1),
		RealAddress:    get(2),
		VirtualAddress: get(3),
		BytesReceived:  bytesRx,
		BytesSent:      bytesTx,
		ConnectedSince: get(7),
		ClientID:       get(10),
		PeerID:         get(11),
		Cipher:         get(12),
	}
}

func splitStatusFields(line string) []string {
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
