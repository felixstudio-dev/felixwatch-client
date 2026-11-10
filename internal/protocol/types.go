package protocol

const ProtocolVersion = "1"

type OperationalState string

const (
	StateHealthy    OperationalState = "HEALTHY"
	StateDegraded   OperationalState = "DEGRADED"
	StateDown       OperationalState = "DOWN"
	StateRecovering OperationalState = "RECOVERING"
	StateRecovered  OperationalState = "RECOVERED"
	StateUnknown    OperationalState = "UNKNOWN"
)

type Causality string

const (
	CausalitySymptom   Causality = "SYMPTOM"
	CausalitySuspected Causality = "SUSPECTED_CAUSE"
	CausalityProbable  Causality = "PROBABLE_CAUSE"
	CausalityConfirmed Causality = "CONFIRMED_CAUSE"
	CausalityUnknown   Causality = "UNKNOWN_CAUSE"
)

type Metrics struct {
	UptimeSeconds    uint64  `json:"uptime_s,omitempty"`
	CPUPercent       float64 `json:"cpu_pct,omitempty"`
	MemoryTotalBytes uint64  `json:"mem_total_b,omitempty"`
	MemoryUsedBytes  uint64  `json:"mem_used_b,omitempty"`
	SwapTotalBytes   uint64  `json:"swap_total_b,omitempty"`
	SwapUsedBytes    uint64  `json:"swap_used_b,omitempty"`
	Load1            float64 `json:"load1,omitempty"`
	DiskUsedPercent  float64 `json:"disk_used_pct,omitempty"`
	InodeUsedPercent float64 `json:"inode_used_pct,omitempty"`
}

type ServiceHealth struct {
	ServiceID string           `json:"service_id"`
	State     OperationalState `json:"state"`
	Essential bool             `json:"essential,omitempty"`
	Detail    string           `json:"detail,omitempty"`
}

type SiteHealth struct {
	SiteID     string           `json:"site_id"`
	State      OperationalState `json:"state"`
	HTTPStatus int              `json:"http_status,omitempty"`
	LatencyMS  int64            `json:"latency_ms,omitempty"`
	Error      string           `json:"error,omitempty"`
}

type Heartbeat struct {
	ProtocolVersion  string          `json:"protocol_version"`
	AgentID          string          `json:"agent_id"`
	CustomerID       string          `json:"customer_id"`
	InfrastructureID string          `json:"infrastructure_id"`
	ServerID         string          `json:"server_id"`
	ObservedAtUnix   int64           `json:"observed_at_unix"`
	Sequence         uint64          `json:"sequence"`
	AgentVersion     string          `json:"agent_version"`
	Metrics          Metrics         `json:"metrics"`
	Services         []ServiceHealth `json:"services,omitempty"`
	Sites            []SiteHealth    `json:"sites,omitempty"`
	Flags            []string        `json:"flags,omitempty"`
}

type ExternalObservation struct {
	CustomerID     string           `json:"customer_id"`
	ServerID       string           `json:"server_id"`
	SiteID         string           `json:"site_id"`
	ObservedAtUnix int64            `json:"observed_at_unix"`
	State          OperationalState `json:"state"`
	HTTPStatus     int              `json:"http_status,omitempty"`
	LatencyMS      int64            `json:"latency_ms,omitempty"`
	Error          string           `json:"error,omitempty"`
}

type IncidentSignal struct {
	ObservedAtUnix  int64            `json:"observed_at_unix"`
	Source          string           `json:"source"`
	State           OperationalState `json:"state"`
	CPUPercent      float64          `json:"cpu_pct,omitempty"`
	MemoryUsedBytes uint64           `json:"mem_used_b,omitempty"`
	DiskUsedPercent float64          `json:"disk_used_pct,omitempty"`
	HTTPStatus      int              `json:"http_status,omitempty"`
	LatencyMS       int64            `json:"latency_ms,omitempty"`
	Services        []ServiceHealth  `json:"services,omitempty"`
}

type IncidentWindow struct {
	IncidentID      string           `json:"incident_id"`
	CustomerID      string           `json:"customer_id"`
	ServerID        string           `json:"server_id"`
	SiteID          string           `json:"site_id"`
	WindowStartUnix int64            `json:"window_start_unix"`
	WindowEndUnix   int64            `json:"window_end_unix"`
	Signals         []IncidentSignal `json:"signals"`
	Truncated       bool             `json:"truncated,omitempty"`
}

type Evidence struct {
	Kind           string `json:"kind"`
	Summary        string `json:"summary"`
	ObservedAtUnix int64  `json:"observed_at_unix"`
}

type Diagnostic struct {
	Causality   Causality  `json:"causality"`
	Summary     string     `json:"summary"`
	Confidence  float64    `json:"confidence"`
	Evidence    []Evidence `json:"evidence,omitempty"`
	Limitations []string   `json:"limitations,omitempty"`
}

type Incident struct {
	IncidentID    string           `json:"incident_id"`
	CustomerID    string           `json:"customer_id"`
	ServerID      string           `json:"server_id"`
	SiteID        string           `json:"site_id"`
	State         OperationalState `json:"state"`
	StartedAtUnix int64            `json:"started_at_unix"`
	EndedAtUnix   int64            `json:"ended_at_unix,omitempty"`
	Diagnostic    Diagnostic       `json:"diagnostic"`
}
