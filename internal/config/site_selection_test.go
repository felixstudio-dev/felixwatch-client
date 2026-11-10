package config

import "testing"

func TestAgentSiteSelectionValidation(t *testing.T) {
	base := AgentConfig{
		CollectorURL: "https://collector.example.test/v1/heartbeat",
		AgentID:      "agent-1", CustomerID: "customer-1", InfrastructureID: "infra-1",
		ServerID: "server-1", SecretEnv: "FW_SECRET", IntervalSeconds: 60,
	}
	tests := []struct {
		name    string
		sites   []SiteConfig
		invalid bool
	}{
		{name: "no selected sites"},
		{name: "explicit selection", sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test/health"}}},
		{name: "local HTTP target", sites: []SiteConfig{{SiteID: "site-a", URL: "http://127.0.0.1:8080/health"}}},
		{name: "duplicate site", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test"}, {SiteID: "site-a", URL: "https://other.test"}}},
		{name: "unsafe identifier", invalid: true, sites: []SiteConfig{{SiteID: "../site", URL: "https://example.test"}}},
		{name: "relative URL", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "/health"}}},
		{name: "non-http scheme", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "file:///etc/passwd"}}},
		{name: "URL credentials", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://user:password@example.test"}}},
		{name: "URL fragment", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test/#private"}}},
		{name: "invalid status", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test", ExpectedStatus: 700}}},
		{name: "negative timeout", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test", TimeoutSeconds: -1}}},
		{name: "unbounded timeout", invalid: true, sites: []SiteConfig{{SiteID: "site-a", URL: "https://example.test", TimeoutSeconds: 31}}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			cfg.Sites = tc.sites
			err := cfg.NormalizeAndValidate()
			if (err != nil) != tc.invalid {
				t.Fatalf("validation error = %v; invalid = %t", err, tc.invalid)
			}
			if err == nil && len(cfg.Sites) > 0 && (cfg.Sites[0].ExpectedStatus != 200 || cfg.Sites[0].TimeoutSeconds != 3) {
				t.Fatal("default selected-site status and timeout must be normalized")
			}
		})
	}
}
