package agent

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/felixstudio-dev/felixwatch-client/internal/protocol"
)

type Sender struct {
	CollectorURL string
	AgentID      string
	Secret       []byte
	Client       *http.Client
}

func NewSender(baseURL, agentID string, secret []byte) *Sender {
	return &Sender{
		CollectorURL: strings.TrimRight(baseURL, "/"),
		AgentID:      agentID,
		Secret:       secret,
		Client:       &http.Client{Timeout: 10 * time.Second},
	}
}

func nonce() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func (s *Sender) Send(ctx context.Context, body []byte) error {
	n, err := nonce()
	if err != nil {
		return errors.New("nonce generation failed")
	}
	ts := time.Now().Unix()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.CollectorURL+"/v1/heartbeat", bytes.NewReader(body))
	if err != nil {
		return errors.New("collector request creation failed")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Felix-Agent-ID", s.AgentID)
	req.Header.Set("X-Felix-Timestamp", fmt.Sprintf("%d", ts))
	req.Header.Set("X-Felix-Nonce", n)
	req.Header.Set("X-Felix-Signature", protocol.Sign(s.Secret, ts, n, body))
	resp, err := s.Client.Do(req)
	if err != nil {
		return errors.New("collector request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("collector returned status %d", resp.StatusCode)
	}
	return nil
}
