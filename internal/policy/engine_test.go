package policy

import (
	"testing"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
)

func TestNewEngine(t *testing.T) {
	e := NewEngine()
	if e == nil { t.Fatal("NewEngine() returned nil") }
	if len(e.rules) == 0 { t.Fatal("Engine has no rules") }
}

func TestBlacklistedProcess_L3Kill(t *testing.T) {
	e := NewEngine()
	blacklisted := []string{"nc", "ncat", "nmap", "hydra", "sqlmap", "mimikatz", "metasploit"}
	for _, comm := range blacklisted {
		ev := models.KernelEvent{Comm: comm, Confidence: 0.5}
		level := e.Evaluate(ev)
		if level != models.L3Kill {
			t.Errorf("Comm=%q: expected L3_KILL, got %s", comm, level)
		}
	}
}

func TestHighConfidence_L3Kill(t *testing.T) {
	e := NewEngine()
	ev := models.KernelEvent{Comm: "unknown_proc", Confidence: 0.95}
	if level := e.Evaluate(ev); level != models.L3Kill {
		t.Errorf("High confidence: expected L3_KILL, got %s", level)
	}
}

func TestMonitoredProcess_L2Contain(t *testing.T) {
	e := NewEngine()
	for _, comm := range []string{"curl", "wget", "bash", "python3"} {
		ev := models.KernelEvent{Comm: comm, Confidence: 0.3}
		level := e.Evaluate(ev)
		if level != models.L2Contain {
			t.Errorf("Comm=%q: expected L2_CONTAIN, got %s", comm, level)
		}
	}
}

func TestMediumConfidence_L2Contain(t *testing.T) {
	e := NewEngine()
	ev := models.KernelEvent{Comm: "unknown", Confidence: 0.75}
	if level := e.Evaluate(ev); level != models.L2Contain {
		t.Errorf("Medium confidence: expected L2_CONTAIN, got %s", level)
	}
}

func TestLowConfidenceUnknown_L1Monitor(t *testing.T) {
	e := NewEngine()
	ev := models.KernelEvent{Comm: "ls", Confidence: 0.1}
	if level := e.Evaluate(ev); level != models.L1Monitor {
		t.Errorf("Low risk: expected L1_MONITOR, got %s", level)
	}
}

func TestBlacklistTakesPriorityOverConfidence(t *testing.T) {
	e := NewEngine()
	// mimikatz with low confidence should still be L3_KILL
	ev := models.KernelEvent{Comm: "mimikatz", Confidence: 0.1}
	if level := e.Evaluate(ev); level != models.L3Kill {
		t.Errorf("Blacklisted low confidence: expected L3_KILL, got %s", level)
	}
}

func TestBoundaryConfidence(t *testing.T) {
	e := NewEngine()
	// Exactly 0.9 → L3_KILL
	ev := models.KernelEvent{Comm: "unknown", Confidence: 0.9}
	if level := e.Evaluate(ev); level != models.L3Kill {
		t.Errorf("Confidence=0.9: expected L3_KILL, got %s", level)
	}
	// Exactly 0.7 → L2_CONTAIN
	ev2 := models.KernelEvent{Comm: "unknown2", Confidence: 0.7}
	if level := e.Evaluate(ev2); level != models.L2Contain {
		t.Errorf("Confidence=0.7: expected L2_CONTAIN, got %s", level)
	}
}
