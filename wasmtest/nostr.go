package wasmtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"ducat/crypto"
	"ducat/shared"
)

// signNostrEvent signs a Nostr event per NIP-01
func signNostrEvent(event *shared.NostrEvent, privKeyBytes []byte) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	if len(privKeyBytes) != 32 {
		return fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privKeyBytes))
	}

	// Serialize event according to NIP-01
	serialized := serializeNostrEvent(event)

	// Compute event ID (SHA256 of serialized event)
	hash := sha256.Sum256([]byte(serialized))
	event.ID = hex.EncodeToString(hash[:])

	// Sign event ID with Schnorr
	sig, err := crypto.SignSchnorr(privKeyBytes, event.ID)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}
	event.Sig = sig

	return nil
}

// serializeNostrEvent serializes event per NIP-01
func serializeNostrEvent(event *shared.NostrEvent) string {
	tags, _ := json.Marshal(event.Tags)
	return fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		event.PubKey, event.CreatedAt, event.Kind, string(tags), event.Content)
}

// verifyNostrEvent verifies a Nostr event per NIP-01
func verifyNostrEvent(event *shared.NostrEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Recompute event ID
	serialized := serializeNostrEvent(event)
	hash := sha256.Sum256([]byte(serialized))
	expectedID := hex.EncodeToString(hash[:])

	if event.ID != expectedID {
		return fmt.Errorf("event ID mismatch: expected %s, got %s", expectedID, event.ID)
	}

	// Verify Schnorr signature
	return crypto.VerifySchnorrEventSignature(event.PubKey, event.ID, event.Sig)
}
