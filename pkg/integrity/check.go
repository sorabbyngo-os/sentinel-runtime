package integrity

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"sync"
)

// Checker maintains a baseline of known-good exe hashes
type Checker struct {
	baseline map[string]string // comm -> sha256 hash
	mu       sync.RWMutex
}

func NewChecker() *Checker {
	return &Checker{
		baseline: make(map[string]string),
	}
}

// Record baseline hash for a process on first seen
func (c *Checker) Record(comm string, pid uint32) error {
	hash, err := hashExe(pid)
	if err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.baseline[comm]; !exists {
		c.baseline[comm] = hash
	}
	return nil
}

// Verify checks if a process matches its baseline hash
// Returns (match, currentHash, baselineHash, error)
func (c *Checker) Verify(comm string, pid uint32) (bool, string, string, error) {
	current, err := hashExe(pid)
	if err != nil {
		return false, "", "", err
	}
	c.mu.RLock()
	baseline, exists := c.baseline[comm]
	c.mu.RUnlock()

	if !exists {
		// First time seeing this process — record and trust
		c.mu.Lock()
		c.baseline[comm] = current
		c.mu.Unlock()
		return true, current, current, nil
	}
	return current == baseline, current, baseline, nil
}

func hashExe(pid uint32) (string, error) {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}
