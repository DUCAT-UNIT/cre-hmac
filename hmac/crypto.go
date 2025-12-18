//go:build wasip1

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"ducat/crypto"
	"ducat/shared"
)

// Cryptographic primitives for DUCAT threshold commitments
// Delegates to non-WASM crypto package for testability

// deriveKeys derives an ECDSA private key and a BIP-340 Schnorr public key from a secp256k1 private key hex string.
// It returns a KeyDerivation containing the private key bytes and Schnorr public key, or an error if derivation fails.
func deriveKeys(privateKeyHex string) (*KeyDerivation, error) {
	kd, err := crypto.DeriveKeys(privateKeyHex)
	if err != nil {
		return nil, err
	}
	return &KeyDerivation{
		PrivateKey:    kd.PrivateKey,
		SchnorrPubkey: kd.SchnorrPubkey,
	}, nil
}

// getPriceCommitHash computes the commitment hash for a price observation
// getPriceCommitHash computes the commitment hash for a price observation defined by the oracle public key, chain network, base price, and base stamp using the provided threshold price.
// It returns the commitment hash as a hex string or an error.
func getPriceCommitHash(oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (string, error) {
	obs := crypto.PriceObservation{
		OraclePubkey: oraclePubkey,
		ChainNetwork: chainNetwork,
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}
	return crypto.GetPriceCommitHash(obs, tholdPrice)
}

// getTholdKey generates threshold key from oracle secret key and commit hash
// getTholdKey computes a threshold key from an oracle secret and a commitment hash.
// The threshold key is produced as HMAC-SHA256 keyed by the oracle secret over the commit hash and returned as a hex string.
// It returns the hex-encoded threshold key or an error from the crypto layer.
func getTholdKey(oracleSeckey, commitHash string) (string, error) {
	return crypto.GetTholdKey(oracleSeckey, commitHash)
}

// getPriceContractID computes the contract ID from commit hash and thold hash
// getPriceContractID computes the price contract identifier from a price commitment hash and a threshold key hash.
// It returns the contract ID string, or an error if the computation fails.
func getPriceContractID(commitHash, tholdHash string) (string, error) {
	return crypto.GetPriceContractID(commitHash, tholdHash)
}

// createPriceContract creates a signed price contract using the oracle secret key and the provided observation fields.
// It returns the constructed *crypto.PriceContract on success, or an error if contract creation fails.
func createPriceContract(oracleSeckey string, oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (*crypto.PriceContract, error) {
	obs := crypto.PriceObservation{
		OraclePubkey: oraclePubkey,
		ChainNetwork: chainNetwork,
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}
	return crypto.CreatePriceContract(oracleSeckey, obs, tholdPrice)
}

// verifyPriceContract verifies the integrity and authenticity of a PriceContract.
// It returns an error if the contract fails verification.
func verifyPriceContract(contract *crypto.PriceContract) error {
	return crypto.VerifyPriceContract(contract)
}

// hash160 computes RIPEMD160(SHA256(data))
func hash160(data []byte) (string, error) {
	return crypto.Hash160(data)
}

// verifyThresholdCommitment verifies secret matches hash160 commitment
func verifyThresholdCommitment(secret, expectedHash string) error {
	return crypto.VerifyThresholdCommitment(secret, expectedHash)
}

// Helper functions for key_rotation.go
func hexToBytes(hexStr string) ([]byte, error) {
	return crypto.HexToBytes(hexStr)
}

func bytesToHex(b []byte) string {
	return crypto.BytesToHex(b)
}

// getPublicKey derives the public key bytes corresponding to the provided private key.
func getPublicKey(privateKey []byte) []byte {
	return crypto.GetPublicKey(privateKey)
}

// signSchnorr creates a BIP-340 Schnorr signature of the provided message using privKeyBytes.
// privKeyBytes must be a 32-byte secp256k1 private key; the function returns the signature as a hex-encoded string or an error if signing fails.
func signSchnorr(privKeyBytes []byte, message string) (string, error) {
	return crypto.SignSchnorr(privKeyBytes, message)
}

// signNostrEvent signs Nostr event per NIP-01
// Mutates event by setting ID and Sig fields
func signNostrEvent(event *NostrEvent, privKeyBytes []byte) error {
	// Validate inputs
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
	sig, err := signSchnorr(privKeyBytes, event.ID)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}
	event.Sig = sig

	return nil
}

// verifyNostrEvent verifies Nostr event per NIP-01
// Validates event ID and Schnorr signature
func verifyNostrEvent(event *NostrEvent) error {
	// Validate input
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	// Recompute event ID from serialized event
	serialized := serializeNostrEvent(event)
	hash := sha256.Sum256([]byte(serialized))
	expectedID := hex.EncodeToString(hash[:])

	// Verify event ID matches (constant-time comparison)
	if subtle.ConstantTimeCompare([]byte(event.ID), []byte(expectedID)) != 1 {
		return fmt.Errorf("event ID mismatch: expected %s, got %s", expectedID, event.ID)
	}

	// Verify Schnorr signature using crypto package
	return crypto.VerifySchnorrEventSignature(event.PubKey, event.ID, event.Sig)
}

// serializeNostrEvent serializes event per NIP-01
// Format: [0, <pubkey>, <created_at>, <kind>, <tags>, <content>]
func serializeNostrEvent(event *NostrEvent) string {
	tags, _ := json.Marshal(event.Tags)
	return fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		event.PubKey, event.CreatedAt, event.Kind, string(tags), event.Content)
}

// validateQuoteAge validates quote timestamp freshness
func validateQuoteAge(quoteStamp, currentTime int64) error {
	return shared.ValidateQuoteAge(quoteStamp, currentTime, MaxQuoteAge)
}