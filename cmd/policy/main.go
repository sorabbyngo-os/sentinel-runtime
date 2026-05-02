package main

import (
	"encoding/json"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/policy"
)

var logger = log.New(os.Stdout, "[POLICY] ", log.LstdFlags)

func main() {
	logger.Println("Sorabbyngo sentinel-runtime policy starting...")

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
	logger.Println("Connected to NATS — policy engine active")

	engine := policy.NewEngine()

	// Evaluate inbound kernel events and publish policy decisions
	nats.Subscribe("sorabbyngo.kcp.>", func(subject, payload string) {
		var ke models.KernelEvent
		if err := json.Unmarshal([]byte(payload), &ke); err != nil {
			return
		}
		level := engine.Evaluate(ke)
		if level == models.L1Monitor {
			return
		}
		decision := models.SentinelDecision{
			Source:     "policy",
			Comm:       ke.Comm,
			PID:        ke.PID,
			Confidence: ke.Confidence,
			Response:   level.String(),
			Message:    ke.Message,
			Action:     level.String(),
			Timestamp:  float64(time.Now().Unix()),
		}
		logger.Printf("POLICY decision: %s pid=%d → %s", ke.Comm, ke.PID, level)
		nats.Publish("sorabbyngo.sentinel.threat", decision)
	})

	go nats.Listen()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Println("Policy engine shutting down")
}
