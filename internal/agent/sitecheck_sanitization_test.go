package agent

import (
	"context"
	"testing"

	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

func TestCheckSitesUsesCategoricalConfigurationError(t *testing.T) {
	results := CheckSites(context.Background(), []config.SiteConfig{{SiteID: "site-a", URL: "://invalid", TimeoutSeconds: 1}})
	if len(results) != 1 {
		t.Fatalf("expected one site result, got %d", len(results))
	}
	if results[0].State != protocol.StateUnknown || results[0].Error != "invalid_local_check_configuration" {
		t.Fatalf("expected sanitized configuration category, got state=%q error=%q", results[0].State, results[0].Error)
	}
}
