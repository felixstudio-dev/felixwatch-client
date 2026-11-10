package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

var safeConfigID = regexp.MustCompile(`^[A-Za-z0-9._-]{1,128}$`)

type SiteConfig struct {
	SiteID         string `json:"site_id"`
	URL            string `json:"url"`
	ExpectedStatus int    `json:"expected_status"`
	TimeoutSeconds int    `json:"timeout_seconds,omitempty"`
}

type ServiceCheckConfig struct {
	ServiceID    string `json:"service_id"`
	PIDFile      string `json:"pid_file"`
	ExpectedComm string `json:"expected_comm,omitempty"`
	Essential    bool   `json:"essential,omitempty"`
}

type AgentConfig struct {
	CollectorURL      string               `json:"collector_url"`
	AgentID           string               `json:"agent_id"`
	CustomerID        string               `json:"customer_id"`
	InfrastructureID  string               `json:"infrastructure_id"`
	ServerID          string               `json:"server_id"`
	SecretEnv         string               `json:"secret_env"`
	IntervalSeconds   int                  `json:"interval_seconds"`
	QueuePath         string               `json:"queue_path"`
	QueueMaxBytes     int64                `json:"queue_max_bytes"`
	AllowInsecureHTTP bool                 `json:"allow_insecure_http,omitempty"`
	Sites             []SiteConfig         `json:"sites,omitempty"`
	Services          []ServiceCheckConfig `json:"services,omitempty"`
}

type AgentIdentity struct {
	AgentID                 string   `json:"agent_id"`
	CustomerID              string   `json:"customer_id"`
	InfrastructureID        string   `json:"infrastructure_id"`
	ServerID                string   `json:"server_id"`
	SiteIDs                 []string `json:"site_ids,omitempty"`
	ServiceIDs              []string `json:"service_ids,omitempty"`
	SecretEnv               string   `json:"secret_env"`
	PreviousSecretEnv       string   `json:"previous_secret_env,omitempty"`
	HeartbeatTimeoutSeconds int      `json:"heartbeat_timeout_seconds,omitempty"`
	Enabled                 bool     `json:"enabled"`
}

type PortalIdentity struct {
	CustomerID       string `json:"customer_id"`
	TokenEnv         string `json:"token_env"`
	PreviousTokenEnv string `json:"previous_token_env,omitempty"`
}

type TelegramConfig struct {
	Enabled     bool   `json:"enabled"`
	BotTokenEnv string `json:"bot_token_env"`
	ChatID      string `json:"chat_id"`
}

type ExternalCheckConfig struct {
	CustomerID       string `json:"customer_id"`
	ServerID         string `json:"server_id"`
	SiteID           string `json:"site_id"`
	URL              string `json:"url"`
	ExpectedStatus   int    `json:"expected_status"`
	ExpectedContains string `json:"expected_contains,omitempty"`
	IntervalSeconds  int    `json:"interval_seconds"`
	TimeoutSeconds   int    `json:"timeout_seconds,omitempty"`
}

type CollectorConfig struct {
	Listen                   string                `json:"listen"`
	DataDir                  string                `json:"data_dir"`
	MaxClockSkewS            int                   `json:"max_clock_skew_seconds"`
	RatePerMinute            int                   `json:"rate_per_minute"`
	IncidentWindowMinutes    int                   `json:"incident_window_minutes,omitempty"`
	IncidentWindowMaxSignals int                   `json:"incident_window_max_signals,omitempty"`
	TelemetryRetentionDays   int                   `json:"telemetry_retention_days,omitempty"`
	Agents                   []AgentIdentity       `json:"agents"`
	Portals                  []PortalIdentity      `json:"portals"`
	Telegram                 TelegramConfig        `json:"telegram"`
	ExternalChecks           []ExternalCheckConfig `json:"external_checks,omitempty"`
}

func Load(path string, dst any) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return fmt.Errorf("decode config: %w", err)
	}
	return nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validateCollectorURL(raw string, allowInsecureHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return errors.New("collector_url must be a valid absolute URL")
	}
	if u.User != nil {
		return errors.New("collector_url must not contain userinfo")
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme != "http" || !allowInsecureHTTP {
		return errors.New("collector_url must use https unless allow_insecure_http is explicitly enabled for loopback development")
	}
	if !isLoopbackHost(u.Hostname()) {
		return errors.New("allow_insecure_http is restricted to loopback collector URLs")
	}
	return nil
}

func validateLoopbackListen(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("collector listen must be host:port: %w", err)
	}
	if !isLoopbackHost(host) {
		return errors.New("collector listen must be loopback; expose Felix Watch through a governed TLS reverse proxy")
	}
	return nil
}

func validateServiceChecks(checks []ServiceCheckConfig) error {
	if len(checks) > 16 {
		return errors.New("services must contain at most 16 explicitly allowlisted checks")
	}
	seen := map[string]bool{}
	for _, check := range checks {
		if check.ServiceID == "" || check.PIDFile == "" {
			return errors.New("every service check requires service_id and pid_file")
		}
		if seen[check.ServiceID] {
			return fmt.Errorf("duplicate service_id %q", check.ServiceID)
		}
		seen[check.ServiceID] = true
		if !filepath.IsAbs(check.PIDFile) {
			return fmt.Errorf("pid_file for service %q must be an absolute path", check.ServiceID)
		}
		if strings.ContainsRune(check.ExpectedComm, '\x00') || len(check.ExpectedComm) > 64 {
			return fmt.Errorf("expected_comm for service %q is invalid", check.ServiceID)
		}
	}
	return nil
}

// validateSiteChecks enforces explicit, unambiguous local site selection.
// The collector independently enforces the authenticated agent's site allowlist.
func validateSiteChecks(sites []SiteConfig) error {
	seen := make(map[string]bool, len(sites))
	for _, site := range sites {
		if !safeConfigID.MatchString(site.SiteID) {
			return errors.New("site check contains an invalid site_id")
		}
		if seen[site.SiteID] {
			return errors.New("site checks contain duplicate site_id")
		}
		seen[site.SiteID] = true
		u, err := url.Parse(site.URL)
		if err != nil || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Fragment != "" {
			return errors.New("site check requires an absolute http(s) URL without credentials or fragment")
		}
		if site.ExpectedStatus < 100 || site.ExpectedStatus > 599 {
			return errors.New("site check expected_status must be a valid HTTP status")
		}
		if site.TimeoutSeconds < 1 || site.TimeoutSeconds > 30 {
			return errors.New("site check timeout_seconds must be between 1 and 30")
		}
	}
	return nil
}

func (c *AgentConfig) NormalizeAndValidate() error {
	if c.IntervalSeconds == 0 {
		c.IntervalSeconds = 60
	}
	if c.IntervalSeconds < 30 {
		return errors.New("interval_seconds must be >= 30")
	}
	if c.QueueMaxBytes == 0 {
		c.QueueMaxBytes = 1 << 20
	}
	if c.QueuePath == "" {
		c.QueuePath = "/var/lib/felixwatch/queue/heartbeats.jsonl"
	}
	if c.AgentID == "" || c.CustomerID == "" || c.InfrastructureID == "" || c.ServerID == "" || c.SecretEnv == "" {
		return errors.New("agent/customer/infrastructure/server IDs and secret_env are required")
	}
	if err := validateCollectorURL(c.CollectorURL, c.AllowInsecureHTTP); err != nil {
		return err
	}
	if err := validateServiceChecks(c.Services); err != nil {
		return err
	}
	for i := range c.Sites {
		if c.Sites[i].ExpectedStatus == 0 {
			c.Sites[i].ExpectedStatus = 200
		}
		if c.Sites[i].TimeoutSeconds == 0 {
			c.Sites[i].TimeoutSeconds = 3
		}
	}
	if err := validateSiteChecks(c.Sites); err != nil {
		return err
	}
	return nil
}

func (c *CollectorConfig) NormalizeAndValidate() error {
	if c.Listen == "" {
		c.Listen = "127.0.0.1:8090"
	}
	if err := validateLoopbackListen(c.Listen); err != nil {
		return err
	}
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.MaxClockSkewS == 0 {
		c.MaxClockSkewS = 120
	}
	if c.RatePerMinute == 0 {
		c.RatePerMinute = 120
	}
	if c.IncidentWindowMinutes == 0 {
		c.IncidentWindowMinutes = 15
	}
	if c.IncidentWindowMinutes < 1 || c.IncidentWindowMinutes > 120 {
		return errors.New("incident_window_minutes must be between 1 and 120")
	}
	if c.IncidentWindowMaxSignals == 0 {
		c.IncidentWindowMaxSignals = 256
	}
	if c.IncidentWindowMaxSignals < 16 || c.IncidentWindowMaxSignals > 1024 {
		return errors.New("incident_window_max_signals must be between 16 and 1024")
	}
	if c.TelemetryRetentionDays == 0 {
		c.TelemetryRetentionDays = 7
	}
	if c.TelemetryRetentionDays < 1 || c.TelemetryRetentionDays > 30 {
		return errors.New("telemetry_retention_days must be between 1 and 30")
	}
	seen := map[string]bool{}
	for i := range c.Agents {
		a := &c.Agents[i]
		if a.AgentID == "" || a.CustomerID == "" || a.InfrastructureID == "" || a.ServerID == "" || a.SecretEnv == "" {
			return errors.New("every agent identity requires IDs and secret_env")
		}
		for _, value := range []string{a.AgentID, a.CustomerID, a.InfrastructureID, a.ServerID} {
			if !safeConfigID.MatchString(value) {
				return errors.New("agent identity contains an unsafe identifier")
			}
		}
		if seen[a.AgentID] {
			return fmt.Errorf("duplicate agent_id %q", a.AgentID)
		}
		seen[a.AgentID] = true
		sites := map[string]bool{}
		for _, siteID := range a.SiteIDs {
			if !safeConfigID.MatchString(siteID) {
				return fmt.Errorf("invalid site_id %q for agent %q", siteID, a.AgentID)
			}
			if sites[siteID] {
				return fmt.Errorf("duplicate site_id %q for agent %q", siteID, a.AgentID)
			}
			sites[siteID] = true
		}
		if len(a.ServiceIDs) > 16 {
			return fmt.Errorf("service_ids for agent %q must contain at most 16 entries", a.AgentID)
		}
		services := map[string]bool{}
		for _, serviceID := range a.ServiceIDs {
			if !safeConfigID.MatchString(serviceID) {
				return fmt.Errorf("invalid service_id %q for agent %q", serviceID, a.AgentID)
			}
			if services[serviceID] {
				return fmt.Errorf("duplicate service_id %q for agent %q", serviceID, a.AgentID)
			}
			services[serviceID] = true
		}
		if a.HeartbeatTimeoutSeconds == 0 {
			a.HeartbeatTimeoutSeconds = 180
		}
		if a.HeartbeatTimeoutSeconds < 60 {
			return fmt.Errorf("heartbeat_timeout_seconds for agent %q must be >= 60", a.AgentID)
		}
	}
	portalSeen := map[string]bool{}
	for _, p := range c.Portals {
		if p.CustomerID == "" || p.TokenEnv == "" {
			return errors.New("every portal identity requires customer_id and token_env")
		}
		if !safeConfigID.MatchString(p.CustomerID) {
			return errors.New("portal identity contains an unsafe customer_id")
		}
		if portalSeen[p.CustomerID] {
			return fmt.Errorf("duplicate portal customer_id %q", p.CustomerID)
		}
		portalSeen[p.CustomerID] = true
	}
	for i := range c.ExternalChecks {
		if c.ExternalChecks[i].ExpectedStatus == 0 {
			c.ExternalChecks[i].ExpectedStatus = 200
		}
		if c.ExternalChecks[i].IntervalSeconds == 0 {
			c.ExternalChecks[i].IntervalSeconds = 60
		}
		if c.ExternalChecks[i].IntervalSeconds < 30 {
			return errors.New("external check interval must be >= 30 seconds")
		}
		if c.ExternalChecks[i].TimeoutSeconds == 0 {
			c.ExternalChecks[i].TimeoutSeconds = 5
		}
	}
	return nil
}

func EnvRequired(name string) (string, error) {
	v := os.Getenv(name)
	if v == "" {
		return "", fmt.Errorf("required environment variable %q is not set", name)
	}
	return v, nil
}

func (c CollectorConfig) MaxClockSkew() time.Duration {
	return time.Duration(c.MaxClockSkewS) * time.Second
}
