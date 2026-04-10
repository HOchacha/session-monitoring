package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"openvpn-session-agent/internal/openvpn"
	"openvpn-session-agent/internal/parser"
	"openvpn-session-agent/internal/shipper"
)

type snapshotSender interface {
	SendMap(context.Context, map[string]any) error
	Close() error
	Mode() string
}

type noopSender struct{}

func (n *noopSender) SendMap(_ context.Context, _ map[string]any) error {
	return nil
}

func (n *noopSender) Close() error {
	return nil
}

func (n *noopSender) Mode() string {
	return "standalone"
}

func main() {
	var (
		mgmtAddr    = flag.String("management-addr", getEnv("OVPN_MGMT_ADDR", "127.0.0.1:7505"), "OpenVPN management interface address")
		grpcTarget  = flag.String("grpc-target", getEnv("ENGINE_GRPC_TARGET", "127.0.0.1:50051"), "Central engine gRPC target")
		grpcMethod  = flag.String("grpc-method", getEnv("ENGINE_GRPC_METHOD", "/openvpn.v1.SessionService/ReportSnapshot"), "gRPC method for snapshot shipping")
		interval    = flag.Duration("interval", getEnvDuration("COLLECT_INTERVAL", 10*time.Second), "Collection interval")
		dialTimeout = flag.Duration("timeout", getEnvDuration("DIAL_TIMEOUT", 5*time.Second), "Dial and RPC timeout")
		standalone  = flag.Bool("standalone", getEnvBool("STANDALONE_MODE", false), "Run without gRPC shipping")
		logPayload  = flag.Bool("log-payload", getEnvBool("LOG_SNAPSHOT_PAYLOAD", true), "Log collected snapshot payload as JSON")
		exportCfg   = flag.String("export-config", getEnv("EXPORT_CONFIG_PATH", ""), "Path to YAML file selecting exported fields")
	)
	flag.Parse()

	cfg, err := loadExportConfig(*exportCfg)
	if err != nil {
		log.Fatalf("failed to load export config: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	ovpn := &openvpn.Client{Address: *mgmtAddr, Timeout: *dialTimeout}

	killCN := cfg.KillCommonName
	killCNMsg := cfg.KillCommonNameMessage

	if killCN != "" {
		var err error
		if killCNMsg != "" {
			err = ovpn.KillByCommonNameWithMessage(killCN, killCNMsg)
		} else {
			err = ovpn.KillByCommonName(killCN)
		}
		if err != nil {
			log.Fatalf("kill common name failed: %v", err)
		}
		if killCNMsg != "" {
			log.Printf("killed client(s) with common_name=%s message=%q", killCN, killCNMsg)
		} else {
			log.Printf("killed client(s) with common_name=%s", killCN)
		}
		return
	}

	var sender snapshotSender
	if *standalone {
		sender = &noopSender{}
		log.Printf("standalone mode enabled: gRPC shipping disabled")
	} else {
		grpcClient := &shipper.Client{Target: *grpcTarget, MethodName: *grpcMethod, Timeout: *dialTimeout}
		if err := grpcClient.Connect(); err != nil {
			log.Printf("grpc connect failed (%v), continuing in standalone mode", err)
			sender = &noopSender{}
		} else {
			sender = grpcClient
		}
	}
	defer func() {
		if err := sender.Close(); err != nil {
			log.Printf("sender close warning: %v", err)
		}
	}()

	ticker := time.NewTicker(*interval)
	defer ticker.Stop()

	log.Printf(
		"openvpn-session-agent started management=%s mode=%s grpc=%s method=%s interval=%s",
		*mgmtAddr,
		sender.Mode(),
		*grpcTarget,
		*grpcMethod,
		interval.String(),
	)

	for {
		if err := collectAndShip(ctx, ovpn, sender, *logPayload, cfg); err != nil {
			log.Printf("collect/ship failed: %v", err)
		}

		select {
		case <-ctx.Done():
			log.Printf("openvpn-session-agent stopping")
			return
		case <-ticker.C:
		}
	}
}

func collectAndShip(ctx context.Context, ovpn *openvpn.Client, sender snapshotSender, logPayload bool, cfg *ExportConfig) error {
	lines, err := ovpn.ReadStatusV3()
	if err != nil {
		return err
	}

	snapshot := parser.ParseStatus(lines)
	payload := map[string]any{
		"collected_at":          snapshot.CollectedAt.Format(time.RFC3339Nano),
		"server_time":           snapshot.ServerTime,
		"server_time_unix":      snapshot.ServerTimeUnix,
		"active_client_count":   snapshot.ActiveClientCount,
		"bytes_received_sum":    snapshot.BytesReceivedSum,
		"bytes_sent_sum":        snapshot.BytesSentSum,
		"sessions":              sessionsToAny(snapshot.Sessions),
		"collector_source":      "openvpn-management-interface",
		"collector_status_type": "status_3",
	}

	payload = applyExportConfig(payload, cfg)

	if logPayload {
		log.Printf("snapshot payload mode=%s data=%s", sender.Mode(), payloadToJSON(payload))
	}

	if err := sender.SendMap(ctx, payload); err != nil {
		return err
	}

	if sender.Mode() == "grpc" {
		log.Printf("snapshot shipped clients=%d bytes_rx=%d bytes_tx=%d", snapshot.ActiveClientCount, snapshot.BytesReceivedSum, snapshot.BytesSentSum)
	} else {
		log.Printf("snapshot collected (standalone) clients=%d bytes_rx=%d bytes_tx=%d", snapshot.ActiveClientCount, snapshot.BytesReceivedSum, snapshot.BytesSentSum)
	}
	return nil
}

func payloadToJSON(payload map[string]any) string {
	b, err := json.Marshal(payload)
	if err != nil {
		return "{\"error\":\"failed to marshal payload\"}"
	}
	return string(b)
}

func sessionsToAny(in []parser.Session) []any {
	out := make([]any, 0, len(in))
	for _, s := range in {
		out = append(out, map[string]any{
			"common_name":     s.CommonName,
			"real_address":    s.RealAddress,
			"virtual_address": s.VirtualAddress,
			"bytes_received":  s.BytesReceived,
			"bytes_sent":      s.BytesSent,
			"connected_since": s.ConnectedSince,
			"client_id":       s.ClientID,
			"peer_id":         s.PeerID,
			"cipher":          s.Cipher,
		})
	}
	return out
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvDuration(key string, fallback time.Duration) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return fallback
	}
	return d
}

func getEnvBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return fallback
	}
	return b
}
