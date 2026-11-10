package protocol

import (
	"encoding/json"
	"testing"
)

func TestRepresentativeHeartbeatRemainsCompact(t *testing.T) {
	hb := Heartbeat{
		ProtocolVersion: ProtocolVersion,
		AgentID:         "agent-01", CustomerID: "customer-01", InfrastructureID: "infra-01", ServerID: "server-01",
		ObservedAtUnix: 1_700_000_000, Sequence: 1, AgentVersion: "0.1.0-foundation",
		Metrics: Metrics{UptimeSeconds: 123456, CPUPercent: 1.2, MemoryTotalBytes: 8 << 30, MemoryUsedBytes: 2 << 30, SwapTotalBytes: 1 << 30, SwapUsedBytes: 10 << 20, Load1: .4, DiskUsedPercent: 42.1, InodeUsedPercent: 2.3},
		Sites:   []SiteHealth{{SiteID: "site-a", State: StateHealthy, HTTPStatus: 200, LatencyMS: 15}},
	}
	b, err := json.Marshal(hb)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) > 2048 {
		t.Fatalf("representative heartbeat grew beyond compactness guardrail: %d bytes", len(b))
	}
}
