package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/bus"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/ingest"
)

var logger = log.New(os.Stdout, "[INGEST] ", log.LstdFlags)

func main() {
	logger.Println("Sorabbyngo sentinel-runtime ingest starting...")

	var nats *events.NATSClient
	var err error
	for i := 0; i < 5; i++ {
		nats, err = events.NewNATSClient()
		if err == nil {
			break
		}
		logger.Printf("NATS unavailable (%v) — retry %d/5", err, i+1)
		time.Sleep(3 * time.Second)
	}
	if err != nil {
		logger.Printf("NATS not available — starting in proc-poll mode")
		nats = nil
	}

	b := bus.New(nats, logger)
	ing := ingest.New(b, nats, logger)
	ing.Start()

	if nats != nil {
		go nats.Listen()
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	logger.Println("Ingest shutting down")
}
