//go:build wasip1

package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"ducat/crypto"
)

// Cryptographic primitives for DUCAT threshold commitments
// Delegates to non-WASM crypto package for testability

// deriveKeys derives ECDSA and Schnorr public keys from secp256k1 private key
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
// Matches TypeScript: get_price_commit_hash(price_config, thold_price)
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
// Matches TypeScript: thold_key = hmac256(oracle_seckey, commit_hash)
func getTholdKey(oracleSeckey, commitHash string) (string, error) {
	return crypto.GetTholdKey(oracleSeckey, commitHash)
}

// getPriceContractID computes the contract ID from commit hash and thold hash
// Matches TypeScript: get_price_contract_id(commit_hash, thold_hash)
func getPriceContractID(commitHash, tholdHash string) (string, error) {
	return crypto.GetPriceContractID(commitHash, tholdHash)
}

// createPriceContract creates a complete signed price contract
func createPriceContract(oracleSeckey string, oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (*crypto.PriceContract, error) {
	obs := crypto.PriceObservation{
		OraclePubkey: oraclePubkey,
		ChainNetwork: chainNetwork,
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}
	return crypto.CreatePriceContract(oracleSeckey, obs, tholdPrice)
}

// verifyPriceContract verifies the integrity and authenticity of a price contract
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

func getPublicKey(privateKey []byte) []byte {
	return crypto.GetPublicKey(privateKey)
}

// signSchnorr creates BIP-340 Schnorr signature
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
	return crypto.ValidateQuoteAge(quoteStamp, currentTime, MaxQuoteAge)
}
