package agent

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/felixstudio-dev/felixwatch-client/internal/config"
	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

func TestCheckSitesOnlyProbesSelectedSites(t *testing.T) {
	var selectedHits, unselectedHits atomic.Int32
	selected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		selectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer selected.Close()
	unselected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unselectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer unselected.Close()

	results := CheckSites(context.Background(), []config.SiteConfig{{SiteID: "selected", URL: selected.URL, ExpectedStatus: 200, TimeoutSeconds: 1}})
	if len(results) != 1 || results[0].SiteID != "selected" || results[0].State != protocol.StateHealthy {
		t.Fatalf("expected only the selected site to be healthy, got %+v", results)
	}
	if selectedHits.Load() != 1 || unselectedHits.Load() != 0 {
		t.Fatalf("unexpected site probe counts: selected=%d, unselected=%d", selectedHits.Load(), unselectedHits.Load())
	}
}

func TestCheckSitesDoesNotFollowRedirectToUnselectedSite(t *testing.T) {
	var unselectedHits atomic.Int32
	unselected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		unselectedHits.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer unselected.Close()
	selected := httptest.NewServer(http.RedirectHandler(unselected.URL, http.StatusFound))
	defer selected.Close()

	results := CheckSites(context.Background(), []config.SiteConfig{{SiteID: "selected", URL: selected.URL, ExpectedStatus: 200, TimeoutSeconds: 1}})
	if len(results) != 1 || results[0].State != protocol.StateDown || results[0].HTTPStatus != http.StatusFound {
		t.Fatalf("redirect must remain a non-followed site result, got %+v", results)
	}
	if unselectedHits.Load() != 0 {
		t.Fatalf("redirect probed %d unselected targets", unselectedHits.Load())
	}
}
