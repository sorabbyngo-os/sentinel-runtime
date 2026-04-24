package secureevent

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
)

type SecureEvent struct {
	ID        string      `json:"id"`
	Stage     string      `json:"stage"`
	Payload   interface{} `json:"payload"`
	Timestamp int64       `json:"timestamp"`
	Signature string      `json:"signature"`
}

// GenerateKeyPair creates a new ed25519 keypair
func GenerateKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	return pub, priv, err
}

// SignEvent signs the event (without signature field)
func SignEvent(event SecureEvent, priv ed25519.PrivateKey) (string, error) {
	event.Signature = ""

	data, err := json.Marshal(event)
	if err != nil {
		return "", err
	}

	sig := ed25519.Sign(priv, data)
	return hex.EncodeToString(sig), nil
}

// VerifyEvent verifies signature
func VerifyEvent(event SecureEvent, pub ed25519.PublicKey) bool {
	sigBytes, err := hex.DecodeString(event.Signature)
	if err != nil {
		return false
	}

	event.Signature = ""
	data, err := json.Marshal(event)
	if err != nil {
		return false
	}

	return ed25519.Verify(pub, data, sigBytes)
}

// NewSecureEvent creates and signs an event
func NewSecureEvent(stage string, payload interface{}, priv ed25519.PrivateKey) (SecureEvent, error) {
	e := SecureEvent{
		ID:        uuid.New().String(),
		Stage:     stage,
		Payload:   payload,
		Timestamp: time.Now().Unix(),
	}

	sig, err := SignEvent(e, priv)
	if err != nil {
		return e, err
	}

	e.Signature = sig
	return e, nil
}

// Basic replay protection (in-memory)
var seenEvents = make(map[string]int64)

func IsReplay(event SecureEvent) bool {
	if _, exists := seenEvents[event.ID]; exists {
		return true
	}
	seenEvents[event.ID] = event.Timestamp
	return false
}
