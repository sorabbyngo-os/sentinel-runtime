package bus

import (
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
)

// Bus is the internal event router — decouples ingest, detect, enforce.
// Events flow: ingest -> Bus.Publish -> detect subscriber -> enforce subscriber
type Bus struct {
	mu          sync.RWMutex
	subscribers map[string][]func(models.KernelEvent)
	nats        *events.NATSClient
	logger      *log.Logger
}

func New(nats *events.NATSClient, logger *log.Logger) *Bus {
	return &Bus{
		subscribers: make(map[string][]func(models.KernelEvent)),
		nats:        nats,
		logger:      logger,
	}
}

// Subscribe registers a handler for a named channel.
// Channels: "kernel_event", "threat", "response"
func (b *Bus) Subscribe(channel string, fn func(models.KernelEvent)) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.subscribers[channel] = append(b.subscribers[channel], fn)
}

// Publish routes an event to all subscribers on the channel
// and mirrors it to NATS if client is available.
func (b *Bus) Publish(channel string, event models.KernelEvent) {
	b.mu.RLock()
	subs := b.subscribers[channel]
	b.mu.RUnlock()

	for _, fn := range subs {
		go func(f func(models.KernelEvent)) {
			defer func() {
				if r := recover(); r != nil {
					b.logger.Printf("[BUS] subscriber panic on %s: %v", channel, r)
				}
			}()
			f(event)
		}(fn)
	}

	// Mirror to NATS
	if b.nats != nil {
		subject := fmt.Sprintf("sorabbyngo.sentinel.%s", channel)
		if err := b.nats.Publish(subject, event); err != nil {
			b.logger.Printf("[BUS] NATS publish failed (%s): %v", subject, err)
		}
	}
}

// PublishThreat publishes a detected threat with response level attached.
func (b *Bus) PublishThreat(event models.KernelEvent, level models.ResponseLevel, reason string) {
	event.Action = level.String()
	event.Message = reason
	b.Publish("threat", event)
	if b.nats != nil {
		payload := map[string]interface{}{
			"event":     event,
			"level":     level.String(),
			"reason":    reason,
			"timestamp": time.Now().UTC().Format(time.RFC3339),
		}
		data, _ := json.Marshal(payload)
		_ = data
		b.nats.Publish("sorabbyngo.sentinel.threat", payload)
	}
}
