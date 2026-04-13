package models

import "time"

// ResponseLevel maps to the L1-L4 enforcement ladder
type ResponseLevel int

const (
	L1Monitor  ResponseLevel = 1
	L2Contain  ResponseLevel = 2
	L3Kill     ResponseLevel = 3
	L4Lockdown ResponseLevel = 4
)

func (r ResponseLevel) String() string {
	switch r {
	case L1Monitor:
		return "L1_MONITOR"
	case L2Contain:
		return "L2_CONTAIN"
	case L3Kill:
		return "L3_KILL"
	case L4Lockdown:
		return "L4_LOCKDOWN"
	default:
		return "UNKNOWN"
	}
}

// KernelEvent is a raw event from KCP eBPF watcher via NATS
type KernelEvent struct {
	Source     string    `json:"source"`
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	Comm       string    `json:"comm"`
	Filename   string    `json:"filename,omitempty"`
	Confidence float64   `json:"confidence"`
	Message    string    `json:"message"`
	Action     string    `json:"action_taken"`
	Timestamp  float64   `json:"timestamp"`
}

// AttestationReport is a signed record of a detection + decision
type AttestationReport struct {
	PID        uint32        `json:"pid"`
	Comm       string        `json:"comm"`
	ExeHash    string        `json:"exe_hash"`
	NodeID     string        `json:"node_id"`
	Sealed     bool          `json:"sealed"`
	Response   ResponseLevel `json:"response"`
	Confidence float64       `json:"confidence"`
	Message    string        `json:"message"`
	Action     string        `json:"action_taken"`
	LatencyMs  float64       `json:"latency_ms"`
	Timestamp  time.Time     `json:"timestamp"`
	Signature  string        `json:"signature,omitempty"`
}

// SentinelDecision is what sentinel-runtime publishes back to NATS
type SentinelDecision struct {
	Source     string        `json:"source"`
	Comm       string        `json:"comm"`
	PID        uint32        `json:"pid"`
	Confidence float64       `json:"confidence"`
	Response   string        `json:"response"`
	Message    string        `json:"message"`
	Action     string        `json:"action_taken"`
	LatencyMs  float64       `json:"latency_ms"`
	Timestamp  float64       `json:"timestamp"`
}
