package config

import "testing"

func TestCollectorIncidentWindowDefaults(t *testing.T) {
	cfg := CollectorConfig{}
	if err := cfg.NormalizeAndValidate(); err != nil {
		t.Fatal(err)
	}
	if cfg.IncidentWindowMinutes != 15 || cfg.IncidentWindowMaxSignals != 256 || cfg.TelemetryRetentionDays != 7 {
		t.Fatalf("unexpected bounded storage defaults: %#v", cfg)
	}
}

func TestCollectorIncidentWindowBounds(t *testing.T) {
	tests := []struct {
		name string
		cfg  CollectorConfig
	}{
		{name: "window above maximum", cfg: CollectorConfig{IncidentWindowMinutes: 121}},
		{name: "signal limit below minimum", cfg: CollectorConfig{IncidentWindowMaxSignals: 15}},
		{name: "signal limit above maximum", cfg: CollectorConfig{IncidentWindowMaxSignals: 1025}},
		{name: "retention above maximum", cfg: CollectorConfig{TelemetryRetentionDays: 31}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.cfg.NormalizeAndValidate(); err == nil {
				t.Fatal("expected invalid bounded storage configuration to fail")
			}
		})
	}
}
