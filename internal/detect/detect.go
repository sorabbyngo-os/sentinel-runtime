package detect

import (
	"log"
	"strings"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/bus"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
	"github.com/sorabbyngo-Labs/sentinel-runtime/pkg/integrity"
)

// Detector subscribes to kernel_event on the bus and applies
// threat detection rules, publishing threats back to the bus.
type Detector struct {
	bus     *bus.Bus
	checker *integrity.Checker
	logger  *log.Logger
}

// Suspicious process names -> immediate L3 kill
var suspiciousProcs = map[string]bool{
	"nc": true, "ncat": true, "nmap": true, "hydra": true,
	"sqlmap": true, "john": true, "hashcat": true, "aircrack-ng": true,
	"msfconsole": true, "msfvenom": true, "mimikatz": true,
	"netcat": true, "socat": true, "cryptominer": true, "xmrig": true,
}

// Monitored process names -> L2 contain + watch
var monitoredProcs = map[string]bool{
	"curl": true, "wget": true, "python3": true, "bash": true,
	"sh": true, "perl": true, "ruby": true,
}

// Suspicious path prefixes
var suspiciousPaths = []string{
	"/tmp/", "/dev/shm/", "/var/tmp/", "/run/shm/",
}

func New(b *bus.Bus, checker *integrity.Checker, logger *log.Logger) *Detector {
	d := &Detector{bus: b, checker: checker, logger: logger}
	b.Subscribe("kernel_event", d.handle)
	return d
}

func (d *Detector) handle(event models.KernelEvent) {
	level, reason := d.classify(event)
	if level == models.L1Monitor && reason == "" {
		return // no threat
	}
	d.logger.Printf("[DETECT] %s pid=%d comm=%s level=%s reason=%s",
		event.Source, event.PID, event.Comm, level, reason)
	d.bus.PublishThreat(event, level, reason)
}

func (d *Detector) classify(event models.KernelEvent) (models.ResponseLevel, string) {
	// Rule 1: known malicious tool
	if suspiciousProcs[event.Comm] {
		return models.L3Kill, "known offensive tool: " + event.Comm
	}

	// Rule 2: high confidence score from ingest
	if event.Confidence >= 0.9 {
		return models.L3Kill, "high confidence threat score"
	}

	// Rule 3: execution from suspicious path
	for _, prefix := range suspiciousPaths {
		if strings.HasPrefix(event.Filename, prefix) {
			return models.L3Kill, "execution from suspicious path: " + event.Filename
		}
	}

	// Rule 4: integrity check failure
	if d.checker != nil && event.PID > 0 {
		match, current, baseline, err := d.checker.Verify(event.Comm, event.PID)
		if err == nil && !match {
			d.logger.Printf("[DETECT] integrity mismatch %s: baseline=%s current=%s",
				event.Comm, baseline, current)
			return models.L3Kill, "binary hash mismatch: " + event.Comm
		}
	}

	// Rule 5: monitored process — log and watch
	if monitoredProcs[event.Comm] {
		return models.L2Contain, "monitored process: " + event.Comm
	}

	// Rule 6: moderate confidence
	if event.Confidence >= 0.6 {
		return models.L2Contain, "moderate confidence threat"
	}

	return models.L1Monitor, ""
}
