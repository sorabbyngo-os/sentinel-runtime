// Package ledger implements the Ring 2 tamper-evident hash-chained audit ledger.
// Every entry contains SHA-256 of the previous entry, making any tampering detectable.
package ledger

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

const GenesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is a single tamper-evident audit record.
type Entry struct {
	Timestamp   time.Time              `json:"timestamp"`
	EventType   string                 `json:"event_type"`
	Component   string                 `json:"component"`
	NodeID      string                 `json:"node_id"`
	Actor       string                 `json:"actor"`
	Resource    string                 `json:"resource"`
	Outcome     string                 `json:"outcome"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	SHA256Prev  string                 `json:"sha256_prev"`
	SHA256Self  string                 `json:"sha256_self"`
}

// hashEntry computes SHA-256 of the entry excluding SHA256Self.
func hashEntry(e Entry) string {
	e.SHA256Self = ""
	data, _ := json.Marshal(e)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Ledger is a thread-safe append-only hash-chained JSONL ledger.
type Ledger struct {
	mu       sync.Mutex
	f        *os.File
	prevHash string
	path     string
	nodeID   string
}

// New opens or creates a ledger at the given path.
func New(path string, nodeID string) (*Ledger, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0750); err != nil {
		return nil, fmt.Errorf("ledger mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_RDWR, 0640)
	if err != nil {
		return nil, fmt.Errorf("ledger open: %w", err)
	}
	l := &Ledger{f: f, path: path, nodeID: nodeID, prevHash: GenesisHash}
	if err := l.loadLastHash(); err != nil {
		return nil, err
	}
	return l, nil
}

// loadLastHash reads the last line of the file to resume the chain.
func (l *Ledger) loadLastHash() error {
	stat, err := l.f.Stat()
	if err != nil || stat.Size() == 0 {
		return nil
	}
	// Read last 4096 bytes to find last line
	size := stat.Size()
	readSize := int64(4096)
	if size < readSize {
		readSize = size
	}
	buf := make([]byte, readSize)
	if _, err := l.f.ReadAt(buf, size-readSize); err != nil {
		return nil
	}
	// Find last complete line
	data := string(buf)
	last := ""
	for i := len(data) - 1; i >= 0; i-- {
		if data[i] == '\n' && i < len(data)-1 {
			last = data[i+1:]
			break
		}
	}
	if last == "" {
		last = data
	}
	var e Entry
	if err := json.Unmarshal([]byte(last), &e); err != nil {
		return nil
	}
	if e.SHA256Self != "" {
		l.prevHash = e.SHA256Self
	}
	return nil
}

// Write appends a new entry to the ledger.
func (l *Ledger) Write(eventType, actor, resource, outcome string, metadata map[string]interface{}) (Entry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	e := Entry{
		Timestamp:  time.Now().UTC(),
		EventType:  eventType,
		Component:  "sentinel-runtime",
		NodeID:     l.nodeID,
		Actor:      actor,
		Resource:   resource,
		Outcome:    outcome,
		Metadata:   metadata,
		SHA256Prev: l.prevHash,
		SHA256Self: "",
	}
	e.SHA256Self = hashEntry(e)
	l.prevHash = e.SHA256Self

	line, err := json.Marshal(e)
	if err != nil {
		return e, fmt.Errorf("ledger marshal: %w", err)
	}
	if _, err := l.f.Write(append(line, '\n')); err != nil {
		return e, fmt.Errorf("ledger write: %w", err)
	}
	return e, nil
}

// ThreatDetected logs a threat detection event.
func (l *Ledger) ThreatDetected(comm string, pid uint32, level, reason, nodeID string) (Entry, error) {
	return l.Write("security.threat", "sentinel", fmt.Sprintf("process/%s/%d", comm, pid), "DETECTED",
		map[string]interface{}{"comm": comm, "pid": pid, "level": level, "reason": reason, "node_id": nodeID})
}

// ResponseTaken logs an enforcement action.
func (l *Ledger) ResponseTaken(comm string, pid uint32, response, outcome string) (Entry, error) {
	return l.Write("security.enforce", "sentinel", fmt.Sprintf("process/%s/%d", comm, pid), outcome,
		map[string]interface{}{"comm": comm, "pid": pid, "response": response})
}

// AttestationIssued logs a signed attestation.
func (l *Ledger) AttestationIssued(comm string, pid uint32, exeHash, response string, confidence float64) (Entry, error) {
	return l.Write("security.attest", "attester", fmt.Sprintf("process/%s/%d", comm, pid), "SUCCESS",
		map[string]interface{}{"comm": comm, "pid": pid, "exe_hash": exeHash, "response": response, "confidence": confidence})
}

// Close flushes and closes the ledger file.
func (l *Ledger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}

// Verify replays the entire ledger and checks chain integrity.
// Returns number of entries verified and any error.
func Verify(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("cannot open ledger: %w", err)
	}
	defer f.Close()

	count := 0
	prev := GenesisHash
	dec := json.NewDecoder(f)
	for dec.More() {
		var e Entry
		if err := dec.Decode(&e); err != nil {
			return count, fmt.Errorf("line %d: invalid JSON: %w", count+1, err)
		}
		if e.SHA256Prev != prev {
			return count, fmt.Errorf("line %d: chain broken — expected prev=%s got=%s", count+1, prev, e.SHA256Prev)
		}
		computed := hashEntry(e)
		if computed != e.SHA256Self {
			return count, fmt.Errorf("line %d: entry tampered — computed=%s recorded=%s", count+1, computed, e.SHA256Self)
		}
		prev = e.SHA256Self
		count++
	}
	return count, nil
}
