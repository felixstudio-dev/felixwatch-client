package config

import "testing"

func validAgentConfig() AgentConfig {
	return AgentConfig{
		CollectorURL:     "https://watch.example.test/v1/heartbeat",
		AgentID:          "agent-1",
		CustomerID:       "customer-1",
		InfrastructureID: "infra-1",
		ServerID:         "server-1",
		SecretEnv:        "FW_SECRET",
		IntervalSeconds:  60,
	}
}

func TestServiceChecksRequireAbsoluteAllowlistedPIDFiles(t *testing.T) {
	cfg := validAgentConfig()
	cfg.Services = []ServiceCheckConfig{{ServiceID: "web", PIDFile: "run/web.pid"}}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatal("relative pid_file must be rejected")
	}

	cfg = validAgentConfig()
	cfg.Services = []ServiceCheckConfig{{ServiceID: "web", PIDFile: "/run/web.pid"}, {ServiceID: "web", PIDFile: "/run/web2.pid"}}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatal("duplicate service_id must be rejected")
	}
}

func TestServiceChecksAreStrictlyBounded(t *testing.T) {
	cfg := validAgentConfig()
	for i := 0; i < 17; i++ {
		cfg.Services = append(cfg.Services, ServiceCheckConfig{ServiceID: string(rune('a' + i)), PIDFile: "/run/service.pid"})
	}
	if err := cfg.NormalizeAndValidate(); err == nil {
		t.Fatal("more than 16 service checks must be rejected")
	}
}
