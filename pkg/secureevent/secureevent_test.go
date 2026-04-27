package secureevent

import (
	"testing"
)

func TestGenerateKeyPair(t *testing.T) {
	pub, priv, err := GenerateKeyPair()
	if err != nil { t.Fatalf("GenerateKeyPair failed: %v", err) }
	if len(pub) == 0 { t.Error("Public key is empty") }
	if len(priv) == 0 { t.Error("Private key is empty") }
}

func TestNewSecureEvent(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	_ = pub
	payload := map[string]string{"comm": "mimikatz", "pid": "1234"}
	e, err := NewSecureEvent("detect", payload, priv)
	if err != nil { t.Fatalf("NewSecureEvent failed: %v", err) }
	if e.ID == "" { t.Error("Event ID is empty") }
	if e.Stage != "detect" { t.Errorf("Stage mismatch: got %q", e.Stage) }
	if e.Signature == "" { t.Error("Signature is empty") }
	if e.Timestamp == 0 { t.Error("Timestamp is zero") }
}

func TestSignAndVerify(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	e, _ := NewSecureEvent("enforce", map[string]string{"action": "kill"}, priv)
	if !VerifyEvent(e, pub) {
		t.Error("VerifyEvent failed for valid signature")
	}
}

func TestVerifyTamperedEvent(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	e, _ := NewSecureEvent("enforce", map[string]string{"action": "kill"}, priv)
	// Tamper with the stage
	e.Stage = "tampered"
	if VerifyEvent(e, pub) {
		t.Error("VerifyEvent should fail for tampered event")
	}
}

func TestVerifyWrongKey(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	wrongPub, _, _ := GenerateKeyPair()
	e, _ := NewSecureEvent("detect", map[string]string{"x": "y"}, priv)
	if VerifyEvent(e, wrongPub) {
		t.Error("VerifyEvent should fail with wrong public key")
	}
}

func TestVerifyInvalidSignature(t *testing.T) {
	pub, priv, _ := GenerateKeyPair()
	e, _ := NewSecureEvent("detect", map[string]string{"x": "y"}, priv)
	e.Signature = "not-a-valid-hex-signature"
	if VerifyEvent(e, pub) {
		t.Error("VerifyEvent should fail with invalid signature hex")
	}
}

func TestReplayProtection(t *testing.T) {
	// Reset seen events for test isolation
	seenEvents = make(map[string]int64)
	_, priv, _ := GenerateKeyPair()
	e, _ := NewSecureEvent("detect", map[string]string{"x": "y"}, priv)
	if IsReplay(e) {
		t.Error("First occurrence should not be a replay")
	}
	if !IsReplay(e) {
		t.Error("Second occurrence should be a replay")
	}
}

func TestUniqueEventIDs(t *testing.T) {
	_, priv, _ := GenerateKeyPair()
	ids := make(map[string]bool)
	for i := 0; i < 10; i++ {
		e, _ := NewSecureEvent("detect", map[string]string{"i": "v"}, priv)
		if ids[e.ID] { t.Errorf("Duplicate event ID: %s", e.ID) }
		ids[e.ID] = true
	}
}
