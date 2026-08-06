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

// deriveKeys derives an ECDSA private key and a BIP-340 Schnorr public key from a secp256k1 private key hex string.
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
func getTholdKey(oracleSeckey, commitHash string) (string, error) {
	return crypto.GetTholdKey(oracleSeckey, commitHash)
}

// getPriceContractID computes the contract ID from commit hash and thold hash
func getPriceContractID(commitHash, tholdHash string) (string, error) {
	return crypto.GetPriceContractID(commitHash, tholdHash)
}

// createPriceContract creates a signed price contract
func createPriceContract(oracleSeckey string, oraclePubkey, chainNetwork string, basePrice, baseStamp, tholdPrice uint32) (*crypto.PriceContract, error) {
	obs := crypto.PriceObservation{
		OraclePubkey: oraclePubkey,
		ChainNetwork: chainNetwork,
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}
	return crypto.CreatePriceContract(oracleSeckey, obs, tholdPrice)
}

// verifyPriceContractResponse validates signed relay content before any breach
// decision or secret derivation. The API shape uses int64, so reject values that
// would wrap when converted to the uint32 commitment format.
func verifyPriceContractResponse(contract *PriceContractResponse) error {
	if contract == nil {
		return fmt.Errorf("price contract cannot be nil")
	}
	maxUint32 := int64(^uint32(0))
	if contract.BasePrice <= 0 || contract.BasePrice > maxUint32 {
		return fmt.Errorf("base_price out of uint32 range: %d", contract.BasePrice)
	}
	if contract.BaseStamp <= 0 || contract.BaseStamp > maxUint32 {
		return fmt.Errorf("base_stamp out of uint32 range: %d", contract.BaseStamp)
	}
	if contract.TholdPrice <= 0 || contract.TholdPrice > maxUint32 {
		return fmt.Errorf("thold_price out of uint32 range: %d", contract.TholdPrice)
	}
	if contract.TholdKey != nil && *contract.TholdKey == "" {
		return fmt.Errorf("revealed thold_key cannot be empty")
	}
	return crypto.VerifyPriceContract(&crypto.PriceContract{
		BasePrice:    uint32(contract.BasePrice),
		BaseStamp:    uint32(contract.BaseStamp),
		ChainNetwork: contract.ChainNetwork,
		CommitHash:   contract.CommitHash,
		ContractID:   contract.ContractID,
		OraclePubkey: contract.OraclePubkey,
		OracleSig:    contract.OracleSig,
		TholdHash:    contract.TholdHash,
		TholdKey:     contract.TholdKey,
		TholdPrice:   uint32(contract.TholdPrice),
	})
}

// verifyThresholdCommitment verifies secret matches hash160 commitment
func verifyThresholdCommitment(secret, expectedHash string) error {
	return crypto.VerifyThresholdCommitment(secret, expectedHash)
}

// signSchnorr creates a BIP-340 Schnorr signature
func signSchnorr(privKeyBytes []byte, message string) (string, error) {
	return crypto.SignSchnorr(privKeyBytes, message)
}

// signNostrEvent signs Nostr event per NIP-01
func signNostrEvent(event *NostrEvent, privKeyBytes []byte) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}
	if len(privKeyBytes) != 32 {
		return fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privKeyBytes))
	}

	serialized := serializeNostrEvent(event)
	hash := sha256.Sum256([]byte(serialized))
	event.ID = hex.EncodeToString(hash[:])

	sig, err := signSchnorr(privKeyBytes, event.ID)
	if err != nil {
		return fmt.Errorf("failed to sign event: %w", err)
	}
	event.Sig = sig

	return nil
}

// verifyNostrEvent verifies Nostr event per NIP-01
func verifyNostrEvent(event *NostrEvent) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	serialized := serializeNostrEvent(event)
	hash := sha256.Sum256([]byte(serialized))
	expectedID := hex.EncodeToString(hash[:])

	if subtle.ConstantTimeCompare([]byte(event.ID), []byte(expectedID)) != 1 {
		return fmt.Errorf("event ID mismatch: expected %s, got %s", expectedID, event.ID)
	}

	return crypto.VerifySchnorrEventSignature(event.PubKey, event.ID, event.Sig)
}

// serializeNostrEvent serializes event per NIP-01
func serializeNostrEvent(event *NostrEvent) string {
	tags, _ := json.Marshal(event.Tags)
	return fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		event.PubKey, event.CreatedAt, event.Kind, string(tags), event.Content)
}
