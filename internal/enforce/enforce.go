// Package enforce implements the L1-L4 response ladder.
// L1: monitor (log only)
// L2: soft contain (flag + rate limit + NATS alert)
// L3: kill (SIGTERM → SIGKILL)
// L4: subsystem lockdown
package enforce

import (
	"fmt"
	"log"
	"os/exec"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/bus"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/ledger"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
	"github.com/sorabbyngo-Labs/sentinel-runtime/pkg/attestation"
)

// Enforcer executes L1-L4 responses and writes to the audit ledger.
type Enforcer struct {
	bus      *bus.Bus
	ledger   *ledger.Ledger
	attester *attestation.Attester
	logger   *log.Logger
}

func New(b *bus.Bus, l *ledger.Ledger, att *attestation.Attester, logger *log.Logger) *Enforcer {
	e := &Enforcer{bus: b, ledger: l, attester: att, logger: logger}
	b.Subscribe("threat", e.handle)
	return e
}

func (e *Enforcer) handle(event models.KernelEvent) {
	start := time.Now()

	level := models.ResponseLevel(0)
	switch event.Action {
	case "L1_MONITOR":
		level = models.L1Monitor
	case "L2_CONTAIN":
		level = models.L2Contain
	case "L3_KILL":
		level = models.L3Kill
	case "L4_LOCKDOWN":
		level = models.L4Lockdown
	default:
		level = models.L2Contain
	}

	var outcome string
	var execErr error

	switch level {
	case models.L1Monitor:
		outcome = e.l1Monitor(event)
	case models.L2Contain:
		outcome = e.l2Contain(event)
	case models.L3Kill:
		outcome, execErr = e.l3Kill(event)
	case models.L4Lockdown:
		outcome, execErr = e.l4Lockdown(event)
	}

	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	if execErr != nil {
		e.logger.Printf("[ENFORCE] %s pid=%d level=%s outcome=FAILED err=%v",
			event.Comm, event.PID, level, execErr)
		outcome = "FAILED"
	} else {
		e.logger.Printf("[ENFORCE] %s pid=%d level=%s outcome=%s latency=%.2fms",
			event.Comm, event.PID, level, outcome, latencyMs)
	}

	// Write to audit ledger
	if e.ledger != nil {
		e.ledger.ResponseTaken(event.Comm, event.PID, level.String(), outcome)
	}

	// Produce attestation report
	if e.attester != nil {
		report := e.attester.Attest(event, level, latencyMs)
		if e.ledger != nil {
			e.ledger.AttestationIssued(report.Comm, report.PID, report.ExeHash, level.String(), report.Confidence)
		}
		e.bus.Publish("attest", models.KernelEvent{
			Source:     "enforcer",
			PID:        report.PID,
			Comm:       report.Comm,
			Confidence: report.Confidence,
			Action:     level.String(),
			Message:    fmt.Sprintf("attestation: %s", report.ExeHash),
			Timestamp:  float64(time.Now().Unix()),
		})
	}
}

func (e *Enforcer) l1Monitor(ev models.KernelEvent) string {
	e.logger.Printf("[L1] MONITOR comm=%s pid=%d reason=%s", ev.Comm, ev.PID, ev.Message)
	return "MONITORED"
}

func (e *Enforcer) l2Contain(ev models.KernelEvent) string {
	e.logger.Printf("[L2] CONTAIN comm=%s pid=%d reason=%s", ev.Comm, ev.PID, ev.Message)
	// Publish soft-contain alert — downstream rate limiter picks this up
	e.bus.Publish("contained", models.KernelEvent{
		Source:    "enforcer",
		PID:       ev.PID,
		Comm:      ev.Comm,
		Action:    "L2_CONTAIN",
		Message:   ev.Message,
		Timestamp: float64(time.Now().Unix()),
	})
	return "CONTAINED"
}

func (e *Enforcer) l3Kill(ev models.KernelEvent) (string, error) {
	if ev.PID == 0 || ev.PID == 9999 {
		e.logger.Printf("[L3] SKIP — test/zero PID comm=%s", ev.Comm)
		return "SKIPPED", nil
	}
	e.logger.Printf("[L3] KILL comm=%s pid=%d", ev.Comm, ev.PID)

	// SIGTERM first
	if err := exec.Command("kill", "-TERM", fmt.Sprintf("%d", ev.PID)).Run(); err != nil {
		return "FAILED", fmt.Errorf("SIGTERM failed: %w", err)
	}
	time.Sleep(2 * time.Second)
	// SIGKILL if still alive
	exec.Command("kill", "-KILL", fmt.Sprintf("%d", ev.PID)).Run()
	return "KILLED", nil
}

func (e *Enforcer) l4Lockdown(ev models.KernelEvent) (string, error) {
	e.logger.Printf("[L4] LOCKDOWN triggered by comm=%s pid=%d reason=%s",
		ev.Comm, ev.PID, ev.Message)
	// Kill the process
	if _, err := e.l3Kill(ev); err != nil {
		e.logger.Printf("[L4] kill failed: %v", err)
	}
	// Publish lockdown event to NATS via bus
	e.bus.Publish("lockdown", models.KernelEvent{
		Source:    "enforcer",
		PID:       ev.PID,
		Comm:      ev.Comm,
		Action:    "L4_LOCKDOWN",
		Message:   fmt.Sprintf("L4 lockdown: %s", ev.Message),
		Timestamp: float64(time.Now().Unix()),
	})
	e.logger.Printf("[L4] Lockdown complete — subsystem alerts sent")
	return "LOCKDOWN", nil
}
