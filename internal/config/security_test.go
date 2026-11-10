package config

import "testing"

func TestCollectorListenMustRemainLoopback(t *testing.T) {
	cases := []struct {
		name    string
		listen  string
		wantErr bool
	}{
		{name: "default ipv4 loopback", listen: "127.0.0.1:8090"},
		{name: "ipv6 loopback", listen: "[::1]:8090"},
		{name: "localhost", listen: "localhost:8090"},
		{name: "all ipv4", listen: "0.0.0.0:8090", wantErr: true},
		{name: "all ipv6", listen: "[::]:8090", wantErr: true},
		{name: "public ip", listen: "203.0.113.10:8090", wantErr: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := CollectorConfig{Listen: tc.listen}
			err := cfg.NormalizeAndValidate()
			if tc.wantErr && err == nil {
				t.Fatalf("expected public/non-loopback listen to be rejected")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected loopback validation error: %v", err)
			}
		})
	}
}

func TestAgentInsecureHTTPOnlyAllowedOnLoopback(t *testing.T) {
	base := AgentConfig{AgentID: "agent-1", CustomerID: "customer-1", InfrastructureID: "infra-1", ServerID: "server-1", SecretEnv: "FW_SECRET", IntervalSeconds: 60}

	https := base
	https.CollectorURL = "https://watch.example.test/v1/heartbeat"
	if err := https.NormalizeAndValidate(); err != nil {
		t.Fatalf("https collector URL should be accepted: %v", err)
	}

	loopback := base
	loopback.CollectorURL = "http://127.0.0.1:8090/v1/heartbeat"
	loopback.AllowInsecureHTTP = true
	if err := loopback.NormalizeAndValidate(); err != nil {
		t.Fatalf("explicit loopback development HTTP should be accepted: %v", err)
	}

	publicHTTP := base
	publicHTTP.CollectorURL = "http://watch.example.test/v1/heartbeat"
	publicHTTP.AllowInsecureHTTP = true
	if err := publicHTTP.NormalizeAndValidate(); err == nil {
		t.Fatal("public HTTP must remain rejected even when allow_insecure_http is set")
	}

	userinfo := base
	userinfo.CollectorURL = "https://user:password@watch.example.test/v1/heartbeat"
	if err := userinfo.NormalizeAndValidate(); err == nil {
		t.Fatal("collector URL userinfo must be rejected to keep credentials out of transport errors")
	}
}

func TestPortalIdentitiesMustBeUniqueAndComplete(t *testing.T) {
	cfg := CollectorConfig{Portals: []PortalIdentity{{CustomerID: "customer-1", TokenEnv: "TOKEN_A"}, {CustomerID: "customer-1", TokenEnv: "TOKEN_B"}}}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatal("duplicate portal customer IDs must be rejected")
	}

	cfg = CollectorConfig{Portals: []PortalIdentity{{CustomerID: "customer-1"}}}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatal("portal without token_env must be rejected")
	}
}

func TestCollectorAgentSiteBindingsMustBeSafeAndUnique(t *testing.T) {
	base := AgentIdentity{AgentID: "agent-1", CustomerID: "customer-1", InfrastructureID: "infra-1", ServerID: "server-1", SecretEnv: "FW_SECRET", Enabled: true}

	valid := CollectorConfig{Agents: []AgentIdentity{base}}
	valid.Agents[0].SiteIDs = []string{"site-a", "site_b"}
	if err := valid.NormalizeAndValidate(); err != nil {
		t.Fatalf("safe unique site bindings should be accepted: %v", err)
	}

	duplicate := CollectorConfig{Agents: []AgentIdentity{base}}
	duplicate.Agents[0].SiteIDs = []string{"site-a", "site-a"}
	if err := duplicate.NormalizeAndValidate(); err == nil {
		t.Fatal("duplicate site bindings must be rejected")
	}

	unsafe := CollectorConfig{Agents: []AgentIdentity{base}}
	unsafe.Agents[0].SiteIDs = []string{"../site-a"}
	if err := unsafe.NormalizeAndValidate(); err == nil {
		t.Fatal("unsafe site bindings must be rejected")
	}
}

func TestCollectorAgentServiceBindingsMustBeBoundedSafeAndUnique(t *testing.T) {
	base := AgentIdentity{AgentID: "agent-1", CustomerID: "customer-1", InfrastructureID: "infra-1", ServerID: "server-1", SecretEnv: "FW_SECRET", Enabled: true}

	valid := CollectorConfig{Agents: []AgentIdentity{base}}
	valid.Agents[0].ServiceIDs = []string{"web", "database"}
	if err := valid.NormalizeAndValidate(); err != nil {
		t.Fatalf("safe unique service bindings should be accepted: %v", err)
	}

	duplicate := CollectorConfig{Agents: []AgentIdentity{base}}
	duplicate.Agents[0].ServiceIDs = []string{"web", "web"}
	if err := duplicate.NormalizeAndValidate(); err == nil {
		t.Fatal("duplicate service bindings must be rejected")
	}

	unsafe := CollectorConfig{Agents: []AgentIdentity{base}}
	unsafe.Agents[0].ServiceIDs = []string{"../web"}
	if err := unsafe.NormalizeAndValidate(); err == nil {
		t.Fatal("unsafe service bindings must be rejected")
	}

	tooMany := CollectorConfig{Agents: []AgentIdentity{base}}
	for i := 0; i < 17; i++ {
		tooMany.Agents[0].ServiceIDs = append(tooMany.Agents[0].ServiceIDs, "service-"+string(rune('a'+i)))
	}
	if err := tooMany.NormalizeAndValidate(); err == nil {
		t.Fatal("more than 16 service bindings must be rejected")
	}
}

func TestCollectorControlPlaneIdentitiesMustBeSafe(t *testing.T) {
	unsafeAgent := CollectorConfig{Agents: []AgentIdentity{{AgentID: "agent\ninjected", CustomerID: "customer-1", InfrastructureID: "infra-1", ServerID: "server-1", SecretEnv: "FW_SECRET", Enabled: true}}}
	if err := unsafeAgent.NormalizeAndValidate(); err == nil {
		t.Fatal("unsafe agent identity must be rejected before it can reach audit logs or storage")
	}

	unsafePortal := CollectorConfig{Portals: []PortalIdentity{{CustomerID: "customer\ninjected", TokenEnv: "FW_PORTAL"}}}
	if err := unsafePortal.NormalizeAndValidate(); err == nil {
		t.Fatal("unsafe portal customer identity must be rejected before it can reach audit logs")
	}
}
