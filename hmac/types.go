//go:build wasip1

package main

import (
	"ducat/shared"

	"github.com/shopspring/decimal"
)

// =============================================================================
// Type Aliases - Import from shared package to avoid duplication
// =============================================================================

// Config is an alias for shared.Config
type Config = shared.Config

// HttpRequestData is an alias for shared.HttpRequestData
type HttpRequestData = shared.HttpRequestData

// EvaluateQuotesRequest is an alias for shared.EvaluateQuotesRequest
type EvaluateQuotesRequest = shared.EvaluateQuotesRequest

// QuoteEvaluationResult is an alias for shared.QuoteEvaluationResult
type QuoteEvaluationResult = shared.QuoteEvaluationResult

// EvaluateQuotesResponse is an alias for shared.EvaluateQuotesResponse
type EvaluateQuotesResponse = shared.EvaluateQuotesResponse

// EvaluationSummary is an alias for shared.EvaluationSummary
type EvaluationSummary = shared.EvaluationSummary

// GenerateQuotesRequest is an alias for shared.GenerateQuotesRequest
type GenerateQuotesRequest = shared.GenerateQuotesRequest

// GenerateQuotesResponse is an alias for shared.GenerateQuotesResponse
type GenerateQuotesResponse = shared.GenerateQuotesResponse

// PriceEvent is an alias for shared.PriceEvent
type PriceEvent = shared.PriceEvent

// NostrEvent is an alias for shared.NostrEvent
type NostrEvent = shared.NostrEvent

// RelayResponse is an alias for shared.RelayResponse
type RelayResponse = shared.RelayResponse

// =============================================================================
// Validation Function Aliases
// =============================================================================

// IsValidTholdHash checks if a string is a valid threshold hash (40 lowercase hex chars)
func IsValidTholdHash(hash string) bool {
	return shared.IsValidTholdHash(hash)
}

// =============================================================================
// WASM-Specific Types (not shared with other packages)
// =============================================================================

// PriceData represents Chainlink price data with consensus aggregation tags
// This is WASM-specific due to the consensus_aggregation struct tags
type PriceData struct {
	Price  decimal.Decimal `json:"price" consensus_aggregation:"median"`
	Origin string          `json:"origin" consensus_aggregation:"identical"`
	Stamp  int64           `json:"stamp" consensus_aggregation:"median"`
}

// KeyDerivation holds derived cryptographic keys
// This is WASM-specific as it's only used in the CRE workflow
type KeyDerivation struct {
	PrivateKey    []byte
	SchnorrPubkey string
}

// Zero securely zeroes the private key bytes to prevent memory leakage.
// SECURITY: Call this via defer immediately after deriveKeys() returns successfully.
func (k *KeyDerivation) Zero() {
	if k != nil && k.PrivateKey != nil {
		for i := range k.PrivateKey {
			k.PrivateKey[i] = 0
		}
	}
}

// BatchGeneratedInfo is sent to gateway after batch quote generation
// Gateway caches this to serve the current base price to clients
type BatchGeneratedInfo struct {
	BasePrice int64 `json:"base_price"` // BTC/USD price used for this batch
	BaseStamp int64 `json:"base_stamp"` // Timestamp when batch was generated
}

// PriceContractResponse is the INTERNAL format for Nostr event storage.
// Contains fields needed for cryptographic verification (commit_hash, contract_id, etc).
// For v2.5 branch: Convert to shared.PriceEvent before sending to gateway/clients.
// For v3 branch: Send directly as the API response format.
type PriceContractResponse struct {
	// PriceObservation fields (from core-ts)
	ChainNetwork string `json:"chain_network"` // Bitcoin network
	OraclePubkey string `json:"oracle_pubkey"` // Server Schnorr public key (32 bytes hex)
	BasePrice    int64  `json:"base_price"`    // Quote creation price
	BaseStamp    int64  `json:"base_stamp"`    // Quote creation timestamp

	// PriceContract fields (from core-ts)
	CommitHash string  `json:"commit_hash"` // hash340(tag, preimage) - 32 bytes hex
	ContractID string  `json:"contract_id"` // hash340(tag, commit||thold) - 32 bytes hex
	OracleSig  string  `json:"oracle_sig"`  // Schnorr signature - 64 bytes hex
	TholdHash  string  `json:"thold_hash"`  // Hash160 commitment - 20 bytes hex
	TholdKey   *string `json:"thold_key"`   // Secret (null if sealed) - 32 bytes hex
	TholdPrice int64   `json:"thold_price"` // Threshold price
}

// ToPriceEvent converts PriceContractResponse to v2.5 PriceEvent format.
// Used on main/v2.5 branch for gateway webhook responses.
func (p *PriceContractResponse) ToPriceEvent(network string) *shared.PriceEvent {
	origin := "cre" // Origin is always "cre" for CRE-generated quotes
	return &shared.PriceEvent{
		// Server identity
		SrvNetwork: network,
		SrvPubkey:  p.OraclePubkey,

		// Quote price (at commitment creation)
		QuoteOrigin: origin,
		QuotePrice:  float64(p.BasePrice),
		QuoteStamp:  p.BaseStamp,

		// Latest price (same as quote for new quotes)
		LatestOrigin: origin,
		LatestPrice:  float64(p.BasePrice),
		LatestStamp:  p.BaseStamp,

		// Event (null for active quotes)
		EventOrigin: nil,
		EventPrice:  nil,
		EventStamp:  nil,
		EventType:   "active",

		// Threshold commitment
		TholdHash:  p.TholdHash,
		TholdKey:   p.TholdKey,
		TholdPrice: float64(p.TholdPrice),

		// State & signatures
		IsExpired: p.TholdKey != nil, // Expired if thold_key is revealed
		ReqID:     p.CommitHash,      // Use commit_hash as request ID
		ReqSig:    p.OracleSig,       // Use oracle_sig as request signature
	}
}
