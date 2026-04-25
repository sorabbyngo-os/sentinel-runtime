package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
)

var logger = log.New(os.Stdout, "[BUS] ", log.LstdFlags)

func main() {
	logger.Println("Sorabbyngo sentinel-runtime bus starting...")

	var nats *events.NATSClient
	var err error
	for i := 0; i < 10; i++ {
		nats, err = events.NewNATSClient()
		if err == nil {
			break
		}
		logger.Printf("NATS unavailable — retrying in 3s")
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		logger.Fatalf("Cannot connect to NATS: %v", err)
	}

	logger.Println("Connected to NATS")
	logger.Println("Bus active — bridging sorabbyngo.kcp.* -> sorabbyngo.sentinel.*")

	// Monitor all sentinel decisions
	nats.Subscribe("sorabbyngo.sentinel.>", func(subject, payload string) {
		logger.Printf("DECISION [%s] %s", subject, payload[:min(len(payload), 100)])
	})

	// Graceful shutdown
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Println("Bus shutting down")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
