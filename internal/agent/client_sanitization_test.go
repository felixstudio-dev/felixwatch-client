package agent

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func TestSenderDoesNotReturnCollectorURLOrTransportErrorContent(t *testing.T) {
	const sentinel = "credential=sensitive-value"
	sender := NewSender("https://user:password@watch.example.test", "agent-a", []byte("signing-key"))
	sender.Client = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New(sentinel + " url=" + req.URL.String())
	})}
	err := sender.Send(context.Background(), []byte(`{"protocol_version":"1"}`))
	if err == nil {
		t.Fatal("expected transport failure")
	}
	for _, forbidden := range []string{sentinel, "password", "watch.example.test"} {
		if strings.Contains(err.Error(), forbidden) {
			t.Fatalf("sender error exposed %q: %v", forbidden, err)
		}
	}
}
