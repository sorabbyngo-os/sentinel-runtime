package main

import (
	"encoding/json"
	"log"
	"os"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/policy"
)

var logger = log.New(os.Stdout, "[POLICY] ", log.LstdFlags)

func main() {
	logger.Println("sentinel-runtime policy engine starting...")

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

	engine := policy.NewEngine()
	logger.Println("Policy engine active — evaluating events from sorabbyngo.kcp.*")

	nats.Subscribe("sorabbyngo.kcp.>", func(subject, payload string) {
		var event models.KernelEvent
		if err := json.Unmarshal([]byte(payload), &event); err != nil {
			return
		}
		response := engine.Evaluate(event)
		logger.Printf("POLICY: %s pid=%d comm=%s -> %s", subject, event.PID, event.Comm, response.String())

		decision := models.SentinelDecision{
			Source:    "sentinel-runtime.policy",
			Comm:      event.Comm,
			PID:       event.PID,
			Confidence: event.Confidence,
			Response:  response.String(),
			Message:   event.Message,
			Timestamp: float64(time.Now().Unix()),
		}

		switch response {
		case models.L3Kill, models.L4Lockdown:
			nats.Publish("sorabbyngo.sentinel.threat", decision)
		case models.L2Contain:
			nats.Publish("sorabbyngo.sentinel.contained", decision)
		default:
			nats.Publish("sorabbyngo.sentinel.learned", decision)
		}
	})

	nats.Listen()
}
