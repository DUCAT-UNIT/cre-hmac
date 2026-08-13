//go:build wasip1

package main

import (
	"fmt"

	"ducat/shared"

	"github.com/shopspring/decimal"
)

// Type aliases from shared package
type (
	Config                 = shared.Config
	HttpRequestData        = shared.HttpRequestData
	EvaluateQuotesRequest  = shared.EvaluateQuotesRequest
	QuoteEvaluationResult  = shared.QuoteEvaluationResult
	EvaluateQuotesResponse = shared.EvaluateQuotesResponse
	EvaluationSummary      = shared.EvaluationSummary
	GenerateQuotesRequest  = shared.GenerateQuotesRequest
	GenerateQuotesResponse = shared.GenerateQuotesResponse
	PriceEvent             = shared.PriceEvent
	NostrEvent             = shared.NostrEvent
)

// RelayResponse with CRE consensus tags
type RelayResponse struct {
	Success bool   `json:"success" consensus_aggregation:"identical"`
	Message string `json:"message" consensus_aggregation:"identical"`
}

func IsValidTholdHash(hash string) bool {
	return shared.IsValidTholdHash(hash)
}

// IsValidQuoteLookupDTag accepts both legacy thold-hash d-tags (40 hex)
// and current commit-hash d-tags (64 hex).
func IsValidQuoteLookupDTag(hash string) bool {
	return shared.IsValidTholdHash(hash) || shared.IsValidCommitHash(hash)
}

// PriceData with CRE consensus tags
type PriceData struct {
	Price  decimal.Decimal `json:"price" consensus_aggregation:"median"`
	Origin string          `json:"origin" consensus_aggregation:"identical"`
	Stamp  int64           `json:"stamp" consensus_aggregation:"median"`
}

// KeyDerivation holds derived cryptographic keys
type KeyDerivation struct {
	PrivateKey    []byte
	SchnorrPubkey string
}

// Zero securely zeroes the private key bytes
func (k *KeyDerivation) Zero() {
	if k != nil && k.PrivateKey != nil {
		for i := range k.PrivateKey {
			k.PrivateKey[i] = 0
		}
	}
}

// PriceContractResponse is the Nostr event content format
type PriceContractResponse struct {
	ChainNetwork string  `json:"chain_network"`
	OraclePubkey string  `json:"oracle_pubkey"`
	BasePrice    int64   `json:"base_price"`
	BaseStamp    int64   `json:"base_stamp"`
	CommitHash   string  `json:"commit_hash"`
	ContractID   string  `json:"contract_id"`
	OracleSig    string  `json:"oracle_sig"`
	TholdHash    string  `json:"thold_hash"`
	TholdKey     *string `json:"thold_key"`
	TholdPrice   int64   `json:"thold_price"`
}

// ToPriceEvent converts to v2.5 PriceEvent format
func (p *PriceContractResponse) ToPriceEvent(network string) *shared.PriceEvent {
	origin := "cre"
	return &shared.PriceEvent{
		SrvNetwork:   network,
		SrvPubkey:    p.OraclePubkey,
		QuoteOrigin:  origin,
		QuotePrice:   float64(p.BasePrice),
		QuoteStamp:   p.BaseStamp,
		LatestOrigin: origin,
		LatestPrice:  float64(p.BasePrice),
		LatestStamp:  p.BaseStamp,
		EventOrigin:  nil,
		EventPrice:   nil,
		EventStamp:   nil,
		EventType:    "active",
		TholdHash:    p.TholdHash,
		TholdKey:     p.TholdKey,
		TholdPrice:   float64(p.TholdPrice),
		IsExpired:    p.TholdKey != nil,
		ReqID:        p.CommitHash,
		ReqSig:       p.OracleSig,
	}
}

// --- Price Adjustment Types ---

// AdjustmentControlDTag is the NIP-33 d-tag used for the price adjustment control event
const AdjustmentControlDTag = "price_adjustment_control"

// PriceAdjustmentRequest is the HTTP request payload for setting a price adjustment
type PriceAdjustmentRequest struct {
	Pct             float64 `json:"pct"`              // Percentage adjustment (e.g., 5.0 = +5%, -10.0 = -10%)
	DurationMinutes int     `json:"duration_minutes"` // How long the adjustment lasts
}

// Validate validates the adjustment request
func (r *PriceAdjustmentRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}
	if r.Pct < -99 || r.Pct > 1000 {
		return fmt.Errorf("pct must be between -99 and 1000, got %.2f", r.Pct)
	}
	if r.DurationMinutes <= 0 {
		return fmt.Errorf("duration_minutes must be positive, got %d", r.DurationMinutes)
	}
	if r.DurationMinutes > 1440 {
		return fmt.Errorf("duration_minutes cannot exceed 1440 (24 hours), got %d", r.DurationMinutes)
	}
	return nil
}

// PriceAdjustmentControl is the content stored in the Nostr control event
type PriceAdjustmentControl struct {
	Pct       float64 `json:"pct"`        // Active percentage adjustment
	ExpiresAt int64   `json:"expires_at"` // Unix timestamp when adjustment expires
	SetAt     int64   `json:"set_at"`     // Unix timestamp when adjustment was set
}

// IsActive returns true if the adjustment is still active (not expired)
func (a *PriceAdjustmentControl) IsActive(currentTime int64) bool {
	return a.Pct != 0 && currentTime < a.ExpiresAt
}

// PriceAdjustmentResponse is the HTTP response for adjust/clear/status actions
type PriceAdjustmentResponse struct {
	Success   bool    `json:"success"`
	Pct       float64 `json:"pct"`
	ExpiresAt int64   `json:"expires_at"`
	SetAt     int64   `json:"set_at"`
	Active    bool    `json:"active"`
	Message   string  `json:"message"`
}

// AdjustmentStatusResponse is returned by the status action with CRE consensus tags
type AdjustmentStatusResponse struct {
	Success   bool    `json:"success" consensus_aggregation:"identical"`
	Active    bool    `json:"active" consensus_aggregation:"identical"`
	Pct       float64 `json:"pct" consensus_aggregation:"median"`
	ExpiresAt int64   `json:"expires_at" consensus_aggregation:"median"`
	SetAt     int64   `json:"set_at" consensus_aggregation:"median"`
	Message   string  `json:"message" consensus_aggregation:"identical"`
}
