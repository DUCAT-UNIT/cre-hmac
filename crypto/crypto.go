package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"golang.org/x/crypto/ripemd160"
)

// Tagged hash tags - matches TypeScript core-ts implementation
const (
	TagPriceCommitHash = "ducat/price_commit_hash"
	TagPriceContractID = "ducat/price_contract_id"
)

// KeyDerivation contains derived cryptographic keys
type KeyDerivation struct {
	PrivateKey    []byte
	SchnorrPubkey string
}

// PriceObservation contains price observation data for commit hash computation.
// Uses uint32 for price/timestamp fields to match core-ts binary serialization:
// Buff.num(base_price, 4) encodes as 4 bytes (uint32) in the commit hash preimage.
// The JSON response layer (PriceContractResponse in types.go) uses int64 for TypeScript compatibility.
type PriceObservation struct {
	OraclePubkey string
	ChainNetwork string
	BasePrice    uint32
	BaseStamp    uint32
}

// PriceContract represents a complete price contract for internal crypto operations.
// Uses uint32 for price/timestamp fields to match core-ts binary serialization (4 bytes each).
// Convert to/from PriceContractResponse (int64) at the API boundary.
type PriceContract struct {
	BasePrice    uint32  `json:"base_price"`
	BaseStamp    uint32  `json:"base_stamp"`
	ChainNetwork string  `json:"chain_network"`
	CommitHash   string  `json:"commit_hash"`
	ContractID   string  `json:"contract_id"`
	OraclePubkey string  `json:"oracle_pubkey"`
	OracleSig    string  `json:"oracle_sig"`
	TholdHash    string  `json:"thold_hash"`
	TholdKey     *string `json:"thold_key"` // null when sealed, revealed when breached
	TholdPrice   uint32  `json:"thold_price"`
}

// HexToBytes decodes a hex-encoded string into the corresponding bytes.
// It returns an error if the input string contains invalid hexadecimal characters or has an odd length.
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

// DeriveKeys derives ECDSA and Schnorr public keys from a secp256k1 private key hex string.
// 
// privateKeyHex is a hex-encoded 32-byte private key. On success it returns a KeyDerivation
// containing the raw private key bytes and the serialized Schnorr public key as a hex string.
// Returns an error if the hex decoding fails or the decoded key is not exactly 32 bytes.
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

// Hash340 computes BIP-340 style tagged hash
// SHA256(SHA256(tag) || SHA256(tag) || data)
// Hash340 computes the BIP-340-style tagged hash of data using tag.
// The result is the 32-byte SHA-256 digest of SHA256(tag) || SHA256(tag) || data.
func Hash340(tag string, data []byte) []byte {
	tagHash := sha256.Sum256([]byte(tag))
	h := sha256.New()
	h.Write(tagHash[:])
	h.Write(tagHash[:])
	h.Write(data)
	return h.Sum(nil)
}

// Hash340Hex returns the hex-encoded BIP-340-style tagged hash of data using tag.
// The tagged hash is computed as SHA256(SHA256(tag) || SHA256(tag) || data) and then hex-encoded.
func Hash340Hex(tag string, data []byte) string {
	return hex.EncodeToString(Hash340(tag, data))
}

// GetPriceCommitHash computes the commitment hash for a price observation and threshold price
// Matches TypeScript: get_price_commit_hash(price_config, thold_price)
// GetPriceCommitHash computes the tagged commit hash for a price observation and threshold price.
// The preimage is: oracle_pubkey (32 bytes) || chain_network (UTF-8 string) || base_price (4 bytes big-endian) || base_stamp (4 bytes big-endian) || thold_price (4 bytes big-endian).
//
// GetPriceCommitHash returns the hex-encoded BIP-340-style tagged hash (using TagPriceCommitHash) of that preimage.
// An error is returned if obs.OraclePubkey is not valid hex or does not decode to 32 bytes.
func GetPriceCommitHash(obs PriceObservation, tholdPrice uint32) (string, error) {
	// Decode oracle pubkey
	pubkeyBytes, err := hex.DecodeString(obs.OraclePubkey)
	if err != nil {
		return "", fmt.Errorf("invalid oracle pubkey hex: %w", err)
	}
	if len(pubkeyBytes) != 32 {
		return "", fmt.Errorf("invalid oracle pubkey length: expected 32 bytes, got %d", len(pubkeyBytes))
	}

	// Build preimage matching TypeScript Buff.join([...])
	preimage := make([]byte, 0, 32+len(obs.ChainNetwork)+4+4+4)
	preimage = append(preimage, pubkeyBytes...)
	preimage = append(preimage, []byte(obs.ChainNetwork)...)

	priceBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(priceBytes, obs.BasePrice)
	preimage = append(preimage, priceBytes...)

	stampBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(stampBytes, obs.BaseStamp)
	preimage = append(preimage, stampBytes...)

	tholdBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(tholdBytes, tholdPrice)
	preimage = append(preimage, tholdBytes...)

	return Hash340Hex(TagPriceCommitHash, preimage), nil
}

// GetTholdKey generates threshold key from oracle secret key and commit hash
// GetTholdKey computes the threshold key as the HMAC-SHA256 of the commit hash using the oracle secret key.
// Both inputs are expected as hex-encoded strings: the oracle secret key must decode to 32 bytes and the commit hash must decode to 32 bytes.
// It returns the hex-encoded HMAC-SHA256 value or an error if either input is invalid.
func GetTholdKey(oracleSeckey string, commitHash string) (string, error) {
	seckeyBytes, err := hex.DecodeString(oracleSeckey)
	if err != nil {
		return "", fmt.Errorf("invalid oracle seckey hex: %w", err)
	}
	if len(seckeyBytes) != 32 {
		return "", fmt.Errorf("invalid oracle seckey length: expected 32 bytes, got %d", len(seckeyBytes))
	}

	commitBytes, err := hex.DecodeString(commitHash)
	if err != nil {
		return "", fmt.Errorf("invalid commit hash hex: %w", err)
	}
	if len(commitBytes) != 32 {
		return "", fmt.Errorf("invalid commit hash length: expected 32 bytes, got %d", len(commitBytes))
	}

	h := hmac.New(sha256.New, seckeyBytes)
	h.Write(commitBytes)
	return hex.EncodeToString(h.Sum(nil)), nil
}

// GetPriceContractID computes the contract ID from commit hash and thold hash
// Matches TypeScript: get_price_contract_id(commit_hash, thold_hash)
// GetPriceContractID computes the price contract identifier from a commit hash and a threshold RIPEMD-160 hash.
// The preimage format is: commit_hash (32 bytes) || thold_hash (20 bytes).
//
// It returns the hex-encoded tagged Hash340 value for the assembled preimage. An error is returned if either
// input is not valid hex or does not decode to the expected length (32 bytes for commitHash, 20 bytes for tholdHash).
func GetPriceContractID(commitHash string, tholdHash string) (string, error) {
	commitBytes, err := hex.DecodeString(commitHash)
	if err != nil {
		return "", fmt.Errorf("invalid commit hash hex: %w", err)
	}
	if len(commitBytes) != 32 {
		return "", fmt.Errorf("invalid commit hash length: expected 32 bytes, got %d", len(commitBytes))
	}

	tholdBytes, err := hex.DecodeString(tholdHash)
	if err != nil {
		return "", fmt.Errorf("invalid thold hash hex: %w", err)
	}
	if len(tholdBytes) != 20 {
		return "", fmt.Errorf("invalid thold hash length: expected 20 bytes, got %d", len(tholdBytes))
	}

	preimage := make([]byte, 0, 52)
	preimage = append(preimage, commitBytes...)
	preimage = append(preimage, tholdBytes...)

	return Hash340Hex(TagPriceContractID, preimage), nil
}

// CreatePriceContract creates a complete signed price contract
// CreatePriceContract constructs a signed PriceContract from an oracle secret key, a price observation, and a threshold price.
// 
// It computes the price commit hash from the observation and threshold, derives a threshold key as HMAC-SHA256(oracleSeckey, commitHash),
// computes the threshold hash as RIPEMD160(SHA256(tholdKey)), derives the contract ID from the commit and threshold hashes,
// and signs the contract ID with the oracle secret key using a Schnorr signature. The returned PriceContract has TholdKey set to the
// hex-encoded threshold key (revealed); callers may nil this field when publishing a sealed contract.
// 
// oracleSeckey must be the hex-encoded 32-byte oracle secret key. obs supplies the oracle public key, chain/network, base price and stamp.
// On success returns a fully populated *PriceContract; on failure returns a non-nil error explaining the failure.
func CreatePriceContract(oracleSeckey string, obs PriceObservation, tholdPrice uint32) (*PriceContract, error) {
	// Compute commit hash
	commitHash, err := GetPriceCommitHash(obs, tholdPrice)
	if err != nil {
		return nil, fmt.Errorf("failed to compute commit hash: %w", err)
	}

	// Compute threshold key: HMAC(oracle_seckey, commit_hash)
	tholdKey, err := GetTholdKey(oracleSeckey, commitHash)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thold key: %w", err)
	}

	// Compute threshold hash: Hash160(thold_key)
	// Must decode hex to bytes first - tholdKey is hex string, hash160 operates on bytes
	tholdKeyBytes, err := hex.DecodeString(tholdKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decode thold key: %w", err)
	}
	tholdHash, err := Hash160(tholdKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to compute thold hash: %w", err)
	}

	// Compute contract ID
	contractID, err := GetPriceContractID(commitHash, tholdHash)
	if err != nil {
		return nil, fmt.Errorf("failed to compute contract id: %w", err)
	}

	// Sign contract ID with oracle secret key
	seckeyBytes, err := hex.DecodeString(oracleSeckey)
	if err != nil {
		return nil, fmt.Errorf("invalid oracle seckey hex: %w", err)
	}

	oracleSig, err := SignSchnorr(seckeyBytes, contractID)
	if err != nil {
		return nil, fmt.Errorf("failed to sign contract: %w", err)
	}

	return &PriceContract{
		BasePrice:    obs.BasePrice,
		BaseStamp:    obs.BaseStamp,
		ChainNetwork: obs.ChainNetwork,
		CommitHash:   commitHash,
		ContractID:   contractID,
		OraclePubkey: obs.OraclePubkey,
		OracleSig:    oracleSig,
		TholdHash:    tholdHash,
		TholdKey:     &tholdKey, // Revealed in creation, set to nil when publishing sealed
		TholdPrice:   tholdPrice,
	}, nil
}

// VerifyPriceContract verifies the integrity and authenticity of a price contract
// VerifyPriceContract validates the integrity and oracle signature of a PriceContract.
// 
// VerifyPriceContract recomputes and checks the contract's commit hash, verifies the revealed
// threshold key against the stored threshold hash when present, recomputes and checks the contract
// ID, and verifies the oracle's Schnorr signature over the contract ID. It returns an error if
// any of these validations fail or if the input contract is nil.
func VerifyPriceContract(contract *PriceContract) error {
	if contract == nil {
		return fmt.Errorf("contract cannot be nil")
	}

	// Recompute commit hash
	obs := PriceObservation{
		OraclePubkey: contract.OraclePubkey,
		ChainNetwork: contract.ChainNetwork,
		BasePrice:    contract.BasePrice,
		BaseStamp:    contract.BaseStamp,
	}
	commitHash, err := GetPriceCommitHash(obs, contract.TholdPrice)
	if err != nil {
		return fmt.Errorf("failed to recompute commit hash: %w", err)
	}
	if commitHash != contract.CommitHash {
		return fmt.Errorf("commit hash mismatch: expected %s, got %s", contract.CommitHash, commitHash)
	}

	// If thold_key is revealed (breach case), verify it matches thold_hash
	if contract.TholdKey != nil && *contract.TholdKey != "" {
		if err := VerifyThresholdCommitment(*contract.TholdKey, contract.TholdHash); err != nil {
			return fmt.Errorf("thold_key does not match thold_hash: %w", err)
		}
	}

	// Recompute contract ID
	contractID, err := GetPriceContractID(commitHash, contract.TholdHash)
	if err != nil {
		return fmt.Errorf("failed to recompute contract id: %w", err)
	}
	if contractID != contract.ContractID {
		return fmt.Errorf("contract id mismatch: expected %s, got %s", contract.ContractID, contractID)
	}

	// Verify oracle signature
	if err := VerifySchnorrSignature(contract.OraclePubkey, contractID, contract.OracleSig); err != nil {
		return fmt.Errorf("oracle signature verification failed: %w", err)
	}

	return nil
}

// Hash160 computes RIPEMD160(SHA256(data))
// Hash160 computes the RIPEMD-160 digest of the SHA-256 hash of data (Bitcoin-style Hash160).
// It returns the resulting 20-byte digest as a lowercase hex string.
// An error is returned if the input data is empty.
func Hash160(data []byte) (string, error) {
	if len(data) == 0 {
		return "", fmt.Errorf("cannot hash empty data")
	}

	sha := sha256.Sum256(data)

	ripemd := ripemd160.New()
	ripemd.Write(sha[:])

	return hex.EncodeToString(ripemd.Sum(nil)), nil
}

// Hash160Bytes computes the RIPEMD-160 digest of the SHA-256 hash of data and returns the resulting 20-byte slice.
// It returns an error if data is empty.
func Hash160Bytes(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("cannot hash empty data")
	}

	sha := sha256.Sum256(data)

	ripemd := ripemd160.New()
	ripemd.Write(sha[:])

	return ripemd.Sum(nil), nil
}

// VerifyThresholdCommitment verifies secret matches hash160 commitment
// VerifyThresholdCommitment verifies that the provided hex-encoded secret matches the expected
// RIPEMD160(SHA256) hash (expressed as a 40-character hex string).
//
// The function decodes `secret` from hex, computes RIPEMD160(SHA256(secretBytes)), and compares
// the resulting hex hash to `expectedHash` using a constant-time comparison. It returns an error
// if inputs are empty, `expectedHash` has an invalid length, the secret is not valid hex, or the
// computed hash does not match `expectedHash`.
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

	// Secret is a hex string, decode to bytes before hashing
	secretBytes, err := hex.DecodeString(secret)
	if err != nil {
		return fmt.Errorf("invalid secret hex: %w", err)
	}

	actualHash, err := Hash160(secretBytes)
	if err != nil {
		return fmt.Errorf("failed to compute hash: %w", err)
	}

	if subtle.ConstantTimeCompare([]byte(actualHash), []byte(expectedHash)) != 1 {
		return fmt.Errorf("commitment verification failed: hash mismatch")
	}

	return nil
}

// SignSchnorr signs a 32-byte message hash with a 32-byte private key using BIP-340 Schnorr
// and returns the serialized signature as a hex-encoded string.
// Errors are returned for invalid key or message lengths, invalid message hex, or if signing fails.
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

// VerifySchnorrEventSignature verifies that sigHex is a valid BIP-340 Schnorr signature
// over the precomputed 32-byte eventID hash using the provided hex-encoded Schnorr public key.
// It returns an error if any hex decoding, parsing, or signature verification fails.
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
