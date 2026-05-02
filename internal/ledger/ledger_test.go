package ledger_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/ledger"
)

func tmpLedger(t *testing.T) (*ledger.Ledger, string) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-audit.jsonl")
	l, err := ledger.New(path, "testnode"+string(make([]byte, 56)))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, path
}

func TestWriteCreatesEntry(t *testing.T) {
	l, _ := tmpLedger(t)
	defer l.Close()
	e, err := l.Write("security.threat", "sentinel", "process/bash/1234", "DETECTED",
		map[string]interface{}{"test": true})
	if err != nil {
		t.Fatalf("Write: %v", err)
	}
	if e.SHA256Self == "" {
		t.Error("SHA256Self should not be empty")
	}
	if e.SHA256Prev != ledger.GenesisHash {
		t.Errorf("first entry SHA256Prev should be genesis hash")
	}
}

func TestChainLinks(t *testing.T) {
	l, _ := tmpLedger(t)
	defer l.Close()
	e1, _ := l.Write("security.threat", "sentinel", "process/bash/1", "DETECTED", nil)
	e2, _ := l.Write("security.threat", "sentinel", "process/nc/2", "BLOCKED", nil)
	if e2.SHA256Prev != e1.SHA256Self {
		t.Errorf("chain broken: e2.prev=%s e1.self=%s", e2.SHA256Prev, e1.SHA256Self)
	}
}

func TestVerifyIntactChain(t *testing.T) {
	l, path := tmpLedger(t)
	for i := 0; i < 10; i++ {
		l.ThreatDetected("bash", uint32(i+1), "L2_CONTAIN", "test", "node1")
	}
	l.Close()
	count, err := ledger.Verify(path)
	if err != nil {
		t.Fatalf("Verify intact chain: %v", err)
	}
	if count != 10 {
		t.Errorf("expected 10 entries, got %d", count)
	}
}

func TestVerifyDetectsTampering(t *testing.T) {
	l, path := tmpLedger(t)
	l.ThreatDetected("bash", 1, "L2_CONTAIN", "test", "node1")
	l.ThreatDetected("nc", 2, "L3_KILL", "offensive tool", "node1")
	l.Close()

	// Tamper with file
	data, _ := os.ReadFile(path)
	tampered := make([]byte, len(data))
	copy(tampered, data)
	// Flip a byte in the middle
	tampered[len(tampered)/2] ^= 0xFF
	os.WriteFile(path, tampered, 0640)

	_, err := ledger.Verify(path)
	if err == nil {
		t.Error("expected verification to fail on tampered data")
	}
}

func TestVerifyDetectsChainBreak(t *testing.T) {
	l, path := tmpLedger(t)
	l.ThreatDetected("bash", 1, "L2_CONTAIN", "test", "node1")
	l.ThreatDetected("nc", 2, "L3_KILL", "offensive tool", "node1")
	l.ThreatDetected("xmrig", 3, "L3_KILL", "cryptominer", "node1")
	l.Close()

	// Delete middle line
	data, _ := os.ReadFile(path)
	lines := splitLines(string(data))
	if len(lines) >= 3 {
		lines = append(lines[:1], lines[2:]...)
	}
	result := ""
	for _, line := range lines {
		result += line + "\n"
	}
	os.WriteFile(path, []byte(result), 0640)

	_, err := ledger.Verify(path)
	if err == nil {
		t.Error("expected chain break detection")
	}
}

func TestPersistenceResumesChain(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.jsonl")

	l1, _ := ledger.New(path, "node1")
	e1, _ := l1.ThreatDetected("bash", 1, "L2", "test", "node1")
	l1.Close()

	l2, _ := ledger.New(path, "node1")
	e2, _ := l2.ThreatDetected("nc", 2, "L3", "tool", "node1")
	l2.Close()

	if e2.SHA256Prev != e1.SHA256Self {
		t.Errorf("persistence chain broken: e2.prev=%s e1.self=%s", e2.SHA256Prev, e1.SHA256Self)
	}

	count, err := ledger.Verify(path)
	if err != nil {
		t.Fatalf("Verify after persistence: %v", err)
	}
	if count != 2 {
		t.Errorf("expected 2 entries, got %d", count)
	}
}

func TestConvenienceMethods(t *testing.T) {
	l, path := tmpLedger(t)
	l.ThreatDetected("nc", 1234, "L3_KILL", "offensive tool", "node1")
	l.ResponseTaken("nc", 1234, "L3_KILL", "KILLED")
	l.AttestationIssued("nc", 1234, "sha256:abc", "L3_KILL", 0.95)
	l.Close()

	count, err := ledger.Verify(path)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if count != 3 {
		t.Errorf("expected 3 entries, got %d", count)
	}
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' {
			if i > start {
				lines = append(lines, s[start:i])
			}
			start = i + 1
		}
	}
	return lines
}
