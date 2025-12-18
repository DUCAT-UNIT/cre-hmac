package wasmtest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"ducat/crypto"
	"ducat/shared"
)

// signNostrEvent signs a Nostr event per NIP-01.
// It sets event.ID to the SHA-256 hex of the NIP-01 serialization and sets event.Sig to the Schnorr signature produced from privKeyBytes.
// Returns an error if event is nil, if privKeyBytes is not 32 bytes, or if signing fails.
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

// serializeNostrEvent produces the NIP-01 serialization of the given event as a JSON-array string containing the event's pubkey, created_at, kind, tags, and content.
// The event's Tags field is JSON-marshaled and inserted verbatim; any marshal error is ignored.
func serializeNostrEvent(event *shared.NostrEvent) string {
	tags, _ := json.Marshal(event.Tags)
	return fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		event.PubKey, event.CreatedAt, event.Kind, string(tags), event.Content)
}

// verifyNostrEvent verifies a Nostr event according to NIP-01 by checking that the SHA-256 hash of the canonical serialization matches event.ID and by validating the Schnorr signature.
// It returns an error if event is nil, if the recomputed ID does not match event.ID, or if signature verification fails.
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