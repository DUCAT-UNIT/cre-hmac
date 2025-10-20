package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/ripemd160"
)

// Domain separators for key derivation
const (
	DomainSeparatorServer    = "DUCAT_SERVER_KEY_V1"
	DomainSeparatorThreshold = "DUCAT_THRESHOLD_V1"
)

// KeyDerivation contains derived cryptographic keys
type KeyDerivation struct {
	PrivateKey    []byte
	SchnorrPubkey string
}

// HexToBytes decodes hex string to bytes
func HexToBytes(hexStr string) ([]byte, error) {
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		return nil, fmt.Errorf("invalid hex: %w", err)
	}
	return b, nil
}

// BytesToHex encodes bytes to hex string
func BytesToHex(b []byte) string {
	return hex.EncodeToString(b)
}

// GetPublicKey derives public key from private key
func GetPublicKey(privateKey []byte) []byte {
	_, pubKey := btcec.PrivKeyFromBytes(privateKey)
	return schnorr.SerializePubKey(pubKey)
}

// DeriveKeys derives ECDSA and Schnorr public keys from secp256k1 private key
func DeriveKeys(privateKeyHex string) (*KeyDerivation, error) {
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid private key hex encoding: %w", err)
	}

	if len(privKeyBytes) != 32 {
		return nil, fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privKeyBytes))
	}

	_, pubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	schnorrPubkey := hex.EncodeToString(schnorr.SerializePubKey(pubKey))

	return &KeyDerivation{
		PrivateKey:    privKeyBytes,
		SchnorrPubkey: schnorrPubkey,
	}, nil
}

// GetServerHMAC generates server-level HMAC key with domain separation
// HMAC-SHA256(privKey, "DUCAT_SERVER_KEY_V1" || domain)
func GetServerHMAC(privateKeyHex, domain string) (string, error) {
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		return "", fmt.Errorf("invalid private key hex: %w", err)
	}

	if len(privKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privKeyBytes))
	}

	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	h := hmac.New(sha256.New, privKeyBytes)
	h.Write([]byte(DomainSeparatorServer))
	h.Write([]byte(domain))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetThresholdKey generates threshold commitment secret
// HMAC-SHA256(serverKey, "DUCAT_THRESHOLD_V1" || domain || quotePrice || quoteStamp || tholdPrice)
func GetThresholdKey(serverHMAC, domain string, quotePrice float64, quoteStamp int64, tholdPrice float64) (string, error) {
	keyBytes, err := hex.DecodeString(serverHMAC)
	if err != nil {
		return "", fmt.Errorf("invalid server HMAC hex: %w", err)
	}

	if len(keyBytes) != 32 {
		return "", fmt.Errorf("invalid server HMAC length: expected 32 bytes, got %d", len(keyBytes))
	}

	if domain == "" {
		return "", fmt.Errorf("domain cannot be empty")
	}

	if quotePrice <= 0 || tholdPrice <= 0 {
		return "", fmt.Errorf("prices must be positive")
	}

	if quoteStamp <= 0 {
		return "", fmt.Errorf("timestamp must be positive")
	}

	h := hmac.New(sha256.New, keyBytes)
	h.Write([]byte(DomainSeparatorThreshold))
	h.Write([]byte(fmt.Sprintf("%s|%.8f|%d|%.8f", domain, quotePrice, quoteStamp, tholdPrice)))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Hash160 computes RIPEMD160(SHA256(data))
// Bitcoin-style commitment hash (20 bytes / 40 hex chars)
func Hash160(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("cannot hash empty data")
	}

	sha := sha256.Sum256(data)

	ripemd := ripemd160.New()
	ripemd.Write(sha[:])

	return hex.EncodeToString(ripemd.Sum(nil)), nil
}

// VerifyThresholdCommitment verifies secret matches hash160 commitment
// Uses constant-time comparison
func VerifyThresholdCommitment(secret, expectedHash string) error {
	if secret == "" {
		return fmt.Errorf("secret cannot be empty")
	}
	if expectedHash == "" {
		return fmt.Errorf("expected hash cannot be empty")
	}

	if len(expectedHash) != 40 {
		return fmt.Errorf("invalid hash length: expected 40 hex chars, got %d", len(expectedHash))
	}

	actualHash, err := Hash160([]byte(secret))
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
		return fmt.Errorf("commitment verification failed: hash mismatch")
	}

	return nil
}

// ComputeRequestID computes deterministic request ID from preimage array
func ComputeRequestID(preimage []interface{}) (string, error) {
	if preimage == nil {
		return "", fmt.Errorf("preimage cannot be nil")
	}

	data, err := json.Marshal(preimage)
	if err != nil {
		return "", fmt.Errorf("failed to serialize preimage: %w", err)
	}

	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:]), nil
}

// SignSchnorr creates BIP-340 Schnorr signature
func SignSchnorr(privKeyBytes []byte, messageHash string) (string, error) {
	if len(privKeyBytes) != 32 {
		return "", fmt.Errorf("invalid private key length: expected 32 bytes, got %d", len(privKeyBytes))
	}

	msgHash, err := hex.DecodeString(messageHash)
	if err != nil {
		return "", fmt.Errorf("invalid message hex: %w", err)
	}

	if len(msgHash) != 32 {
		return "", fmt.Errorf("invalid message length: expected 32 bytes, got %d", len(msgHash))
	}

	privKey, _ := btcec.PrivKeyFromBytes(privKeyBytes)

	sig, err := schnorr.Sign(privKey, msgHash)
	if err != nil {
		return "", fmt.Errorf("schnorr signing failed: %w", err)
	}

	return hex.EncodeToString(sig.Serialize()), nil
}

// VerifySchnorrSignature verifies BIP-340 Schnorr signature
func VerifySchnorrSignature(pubKeyHex, messageHash, sigHex string) error {
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr signature: %w", err)
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr public key: %w", err)
	}

	msgHash, err := hex.DecodeString(messageHash)
	if err != nil {
		return fmt.Errorf("invalid message hex: %w", err)
	}

	if !sig.Verify(msgHash, pubKey) {
		return fmt.Errorf("schnorr signature verification failed")
	}

	return nil
}

// ValidateQuoteAge validates quote timestamp freshness
func ValidateQuoteAge(quoteStamp, currentTime, maxAge int64) error {
	if quoteStamp <= 0 {
		return fmt.Errorf("invalid quote timestamp: must be positive")
	}
	if currentTime <= 0 {
		return fmt.Errorf("invalid current time: must be positive")
	}

	age := currentTime - quoteStamp

	if age < 0 {
		return fmt.Errorf("quote timestamp is in the future")
	}

	if age > maxAge {
		return fmt.Errorf("quote expired: age %d seconds exceeds maximum %d seconds", age, maxAge)
	}

	return nil
}

// VerifySchnorrEventSignature verifies Schnorr signature for pre-computed hash
func VerifySchnorrEventSignature(pubKeyHex, eventID, sigHex string) error {
	// Decode signature
	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return fmt.Errorf("invalid signature hex: %w", err)
	}

	// Parse Schnorr signature
	sig, err := schnorr.ParseSignature(sigBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr signature: %w", err)
	}

	// Decode public key
	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return fmt.Errorf("invalid public key hex: %w", err)
	}

	// Parse Schnorr public key
	pubKey, err := schnorr.ParsePubKey(pubKeyBytes)
	if err != nil {
		return fmt.Errorf("invalid schnorr public key: %w", err)
	}

	// Decode event ID (message hash)
	eventIDBytes, err := hex.DecodeString(eventID)
	if err != nil {
		return fmt.Errorf("invalid event ID hex: %w", err)
	}

	// Verify signature
	if !sig.Verify(eventIDBytes, pubKey) {
		return fmt.Errorf("schnorr signature verification failed")
	}

	return nil
}
