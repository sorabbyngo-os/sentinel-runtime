package attestation

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
)

const NodeIDPath = "/proc/sorabbyngo/nodeid"

// Attester produces signed attestation reports for processes
type Attester struct {
	NodeID string
	Sealed bool
}

func NewAttester() *Attester {
	a := &Attester{}
	if data, err := os.ReadFile(NodeIDPath); err == nil {
		a.NodeID = string(data)
		a.Sealed = true
	} else {
		a.NodeID = "unsealed"
		a.Sealed = false
	}
	return a
}

// HashExe computes SHA256 of the process executable
func HashExe(pid uint32) (string, error) {
	exePath := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := os.Open(exePath)
	if err != nil {
		return "", fmt.Errorf("cannot open exe for pid %d: %w", pid, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// Attest produces an attestation report for a kernel event
func (a *Attester) Attest(
	event models.KernelEvent,
	response models.ResponseLevel,
	latencyMs float64,
) models.AttestationReport {
	exeHash, _ := HashExe(event.PID)

	return models.AttestationReport{
		PID:        event.PID,
		Comm:       event.Comm,
		ExeHash:    exeHash,
		NodeID:     a.NodeID,
		Sealed:     a.Sealed,
		Response:   response,
		Confidence: event.Confidence,
		Message:    event.Message,
		Action:     event.Action,
		LatencyMs:  latencyMs,
		Timestamp:  time.Now(),
	}
}
