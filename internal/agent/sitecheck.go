package agent

import (
	"context"
	"net/http"
	"time"

	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

// Redirects must not extend a selected site's probe to an unselected target.
var siteCheckClient = &http.Client{
	CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse },
}

func CheckSites(ctx context.Context, sites []config.SiteConfig) []protocol.SiteHealth {
	results := make([]protocol.SiteHealth, 0, len(sites))
	for _, s := range sites {
		start := time.Now()
		timeout := time.Duration(s.TimeoutSeconds) * time.Second
		cctx, cancel := context.WithTimeout(ctx, timeout)
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, s.URL, nil)
		if err != nil {
			cancel()
			results = append(results, protocol.SiteHealth{SiteID: s.SiteID, State: protocol.StateUnknown, Error: "invalid_local_check_configuration"})
			continue
		}
		resp, err := siteCheckClient.Do(req)
		latency := time.Since(start).Milliseconds()
		if err != nil {
			cancel()
			results = append(results, protocol.SiteHealth{SiteID: s.SiteID, State: protocol.StateDown, LatencyMS: latency, Error: "local_check_failed"})
			continue
		}
		_ = resp.Body.Close()
		cancel()
		state := protocol.StateHealthy
		if resp.StatusCode != s.ExpectedStatus {
			state = protocol.StateDown
		}
		results = append(results, protocol.SiteHealth{SiteID: s.SiteID, State: state, HTTPStatus: resp.StatusCode, LatencyMS: latency})
	}
	return results
}
