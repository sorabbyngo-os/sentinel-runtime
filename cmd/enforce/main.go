package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
)

var logger = log.New(os.Stdout, "[ENFORCE] ", log.LstdFlags)

func main() {
	logger.Println("Sorabbyngo sentinel-runtime enforce starting...")

	var nats *events.NATSClient
	var err error
	for i := 0; i < 10; i++ {
		nats, err = events.NewNATSClient()
		if err == nil {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		logger.Fatalf("Cannot connect to NATS: %v", err)
	}
	logger.Println("Connected to NATS — enforcer active")

	nats.Subscribe("sorabbyngo.sentinel.threat", func(subject, payload string) {
		var decision models.SentinelDecision
		if err := json.Unmarshal([]byte(payload), &decision); err != nil {
			return
		}
		logger.Printf("ENFORCE L3_KILL: %s pid=%d", decision.Comm, decision.PID)
		enforce(decision)
	})

	nats.Listen()
}

func enforce(d models.SentinelDecision) {
	if d.Comm == "" {
		logger.Printf("ENFORCE skipped — no attestation source")
		return
	}
	if d.PID == 0 || d.PID == 9999 {
		logger.Printf("ENFORCE skipped — test PID or zero PID")
		return
	}
	// L3 — send SIGTERM first, then SIGKILL after 2s
	cmd := exec.Command("kill", "-TERM", fmt.Sprintf("%d", d.PID))
	if err := cmd.Run(); err != nil {
		logger.Printf("SIGTERM failed for pid=%d: %v", d.PID, err)
		return
	}
	logger.Printf("SIGTERM sent to pid=%d (%s)", d.PID, d.Comm)
	time.Sleep(2 * time.Second)
	exec.Command("kill", "-KILL", fmt.Sprintf("%d", d.PID)).Run()
}
