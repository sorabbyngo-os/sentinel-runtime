package models

import (
	"testing"
)

func TestResponseLevelString(t *testing.T) {
	cases := []struct {
		level    ResponseLevel
		expected string
	}{
		{L1Monitor, "L1_MONITOR"},
		{L2Contain, "L2_CONTAIN"},
		{L3Kill, "L3_KILL"},
		{L4Lockdown, "L4_LOCKDOWN"},
		{ResponseLevel(99), "UNKNOWN"},
	}
	for _, c := range cases {
		if got := c.level.String(); got != c.expected {
			t.Errorf("ResponseLevel(%d).String() = %q, want %q", c.level, got, c.expected)
		}
	}
}

func TestKernelEventFields(t *testing.T) {
	e := KernelEvent{
		Source:     "kcp",
		PID:        1234,
		PPID:       1,
		Comm:       "mimikatz",
		Confidence: 0.95,
		Message:    "credential tool detected",
	}
	if e.Source != "kcp" { t.Error("Source mismatch") }
	if e.PID != 1234 { t.Error("PID mismatch") }
	if e.Confidence != 0.95 { t.Error("Confidence mismatch") }
}

func TestAttestationReportFields(t *testing.T) {
	r := AttestationReport{
		PID:        5678,
		Comm:       "ncat",
		ExeHash:    "deadbeef",
		NodeID:     "node-abc123",
		Sealed:     true,
		Response:   L3Kill,
		Confidence: 0.92,
	}
	if r.Response != L3Kill { t.Error("Response mismatch") }
	if !r.Sealed { t.Error("Sealed mismatch") }
	if r.Response.String() != "L3_KILL" { t.Error("String() mismatch") }
}
