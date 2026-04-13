package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
	"github.com/sorabbyngo-Labs/sentinel-runtime/pkg/attestation"
	"github.com/sorabbyngo-Labs/sentinel-runtime/pkg/integrity"
)

var (
	nats     *events.NATSClient
	attester *attestation.Attester
	checker  *integrity.Checker
	logger   = log.New(os.Stdout, "[DETECT] ", log.LstdFlags)
)

// Suspicious processes — L3 response
var suspiciousComms = map[string]bool{
	"nc": true, "ncat": true, "nmap": true, "hydra": true,
	"sqlmap": true, "john": true, "hashcat": true, "aircrack": true,
	"mimikatz": true, "metasploit": true,
}

// Monitored processes — L2 response
var monitoredComms = map[string]bool{
	"curl": true, "wget": true, "python3": true, "bash": true,
}

func decide(event models.KernelEvent) models.ResponseLevel {
	if suspiciousComms[event.Comm] {
		return models.L3Kill
	}
	if event.Confidence >= 0.9 {
		return models.L3Kill
	}
	if monitoredComms[event.Comm] || event.Confidence >= 0.7 {
		return models.L2Contain
	}
	if event.Confidence >= 0.5 {
		return models.L2Contain
	}
	return models.L1Monitor
}

func onKCPEvent(subject, payload string) {
	t0 := time.Now()

	var event models.KernelEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		return
	}

	// Integrity check
	match, current, baseline, err := checker.Verify(event.Comm, event.PID)
	if err == nil && !match {
		logger.Printf("INTEGRITY VIOLATION: %s pid=%d current=%s baseline=%s",
			event.Comm, event.PID, current[:16], baseline[:16])
		event.Confidence = 0.95
	}

	// Decision
	response  := decide(event)
	latencyMs := float64(time.Since(t0).Microseconds()) / 1000.0

	// Attest
	report := attester.Attest(event, response, latencyMs)

	logger.Printf("%s | %s | pid=%d | conf=%.2f | %.2fms",
		response.String(), event.Comm, event.PID, event.Confidence, latencyMs)

	// Publish decision
	decision := models.SentinelDecision{
		Source:     "sentinel-runtime.detect",
		Comm:       event.Comm,
		PID:        event.PID,
		Confidence: event.Confidence,
		Response:   response.String(),
		Message:    event.Message,
		Action:     fmt.Sprintf("%s — runtime attested", response.String()),
		LatencyMs:  latencyMs,
		Timestamp:  float64(time.Now().Unix()),
	}

	subject_out := subjectForResponse(response)
	if err := nats.Publish(subject_out, decision); err != nil {
		logger.Printf("Publish error: %v", err)
	}

	// Publish attestation report
	nats.Publish("sorabbyngo.sentinel.attest", report)
	_ = report
}

func subjectForResponse(r models.ResponseLevel) string {
	switch r {
	case models.L3Kill, models.L4Lockdown:
		return "sorabbyngo.sentinel.threat"
	case models.L2Contain:
		return "sorabbyngo.sentinel.contained"
	default:
		return "sorabbyngo.sentinel.learned"
	}
}

func main() {
	logger.Println("Sorabbyngo sentinel-runtime detect engine starting...")

	var err error
	for i := 0; i < 10; i++ {
		nats, err = events.NewNATSClient()
		if err == nil {
			break
		}
		logger.Printf("NATS unavailable: %v — retrying in 3s", err)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		logger.Fatalf("Cannot connect to NATS: %v", err)
	}
	logger.Println("Connected to NATS")

	attester = attestation.NewAttester()
	checker  = integrity.NewChecker()

	logger.Printf("NodeID sealed: %v", attester.Sealed)
	logger.Println("Subscribing to sorabbyngo.kcp.*")

	nats.Subscribe("sorabbyngo.kcp.>", onKCPEvent)
	logger.Println("Detection engine active — L1/L2/L3/L4 response ladder ready")

	nats.Listen()
}
