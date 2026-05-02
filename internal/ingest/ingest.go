// Package ingest reads kernel events from NATS sorabbyngo.kcp.* and the
// local /proc filesystem, feeding them into the internal bus for detection.
package ingest

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/bus"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/events"
	"github.com/sorabbyngo-Labs/sentinel-runtime/internal/models"
)

// Ingestor reads kernel events and publishes them to the internal bus.
type Ingestor struct {
	bus    *bus.Bus
	nats   *events.NATSClient
	logger *log.Logger
	nodeID string
}

func New(b *bus.Bus, nats *events.NATSClient, logger *log.Logger) *Ingestor {
	nodeID := readNodeID()
	return &Ingestor{bus: b, nats: nats, logger: logger, nodeID: nodeID}
}

func readNodeID() string {
	if data, err := os.ReadFile("/proc/sorabbyngo/nodeid"); err == nil {
		return strings.TrimSpace(string(data))
	}
	if v := os.Getenv("SORABBYNGO_NODE_ID"); v != "" {
		return v
	}
	return "unsealed"
}

// Start subscribes to NATS kernel events and begins polling /proc.
func (ing *Ingestor) Start() {
	ing.logger.Println("Ingestor starting — subscribing to sorabbyngo.kcp.*")

	if ing.nats != nil {
		ing.nats.Subscribe("sorabbyngo.kcp.>", ing.handleNATSEvent)
		ing.logger.Println("Subscribed to sorabbyngo.kcp.*")
	} else {
		ing.logger.Println("NATS unavailable — proc-poll mode only")
		go ing.pollProc()
	}
}

// handleNATSEvent parses a raw KCP event from NATS and publishes to bus.
func (ing *Ingestor) handleNATSEvent(subject, payload string) {
	var ke models.KernelEvent
	if err := json.Unmarshal([]byte(payload), &ke); err != nil {
		ing.logger.Printf("[INGEST] bad payload on %s: %v", subject, err)
		return
	}
	ke.Source = subject
	if ke.Timestamp == 0 {
		ke.Timestamp = float64(time.Now().Unix())
	}
	ing.logger.Printf("[INGEST] kcp event: comm=%s pid=%d conf=%.2f", ke.Comm, ke.PID, ke.Confidence)
	ing.bus.Publish("kernel_event", ke)
}

// pollProc scans /proc for new processes when NATS is unavailable.
// Publishes low-confidence events for known monitored processes.
func (ing *Ingestor) pollProc() {
	ing.logger.Println("[INGEST] proc-poll mode — scanning /proc every 5s")
	seen := make(map[uint32]bool)

	for {
		time.Sleep(5 * time.Second)
		entries, err := os.ReadDir("/proc")
		if err != nil {
			continue
		}
		for _, entry := range entries {
			pid64, err := strconv.ParseUint(entry.Name(), 10, 32)
			if err != nil {
				continue
			}
			pid := uint32(pid64)
			if seen[pid] {
				continue
			}
			seen[pid] = true
			comm := readComm(pid)
			if comm == "" {
				continue
			}
			ke := models.KernelEvent{
				Source:     "proc_poll",
				PID:        pid,
				Comm:       comm,
				Confidence: 0.3,
				Timestamp:  float64(time.Now().Unix()),
				Message:    fmt.Sprintf("proc_poll: new process %s/%d", comm, pid),
			}
			ing.bus.Publish("kernel_event", ke)
		}
	}
}

func readComm(pid uint32) string {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
