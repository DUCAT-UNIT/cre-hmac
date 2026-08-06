//go:build wasip1

package main

import (
	"ducat/shared"
	"fmt"

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

// AdjustmentControlDTag is the NIP-33 d-tag used for the price adjustment control event
const AdjustmentControlDTag = "price_adjustment_control"

// CurrentSnapshotKind ("kind 10000") is the price snapshot wallets read.
// The unified cycle publishes this only after the matching kind-30000 ladder
// has been fully written to the relay, so any kind-10000 wallets see is
// guaranteed to have its ladder available via #h-tag lookup.
const CurrentSnapshotKind = 10000

// PendingSnapshotKind ("kind 10001") is the intermediate snapshot the unified
// cycle writes before publishing the ladder. It is kept as a published
// artifact for observability (e.g. inspecting a cycle that failed before
// step 5) but wallets MUST NOT read this kind — only kind-10000 is
// guaranteed to have a matching ladder.
const PendingSnapshotKind = 10001

// PriceAdjustmentRequest is the HTTP request payload for setting a price adjustment.
type PriceAdjustmentRequest struct {
	Pct             float64 `json:"pct"`
	DurationMinutes int     `json:"duration_minutes"`
}

func (r *PriceAdjustmentRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}
	// SECURITY (H5): cap how far the override may move the published price. A
	// price that drives liquidations must not be pinnable arbitrarily far from
	// the real Chainlink price.
	if r.Pct < MinAdjustmentPct || r.Pct > MaxAdjustmentPct {
		return fmt.Errorf("pct must be between %.0f and %.0f, got %.2f", MinAdjustmentPct, MaxAdjustmentPct, r.Pct)
	}
	if r.DurationMinutes <= 0 {
		return fmt.Errorf("duration_minutes must be positive, got %d", r.DurationMinutes)
	}
	// SECURITY (H5): the override is short-lived by design — it must auto-expire
	// quickly so a stale or compromised control event cannot hold the price off
	// market for long.
	if r.DurationMinutes > MaxAdjustmentDurationMin {
		return fmt.Errorf("duration_minutes cannot exceed %d, got %d", MaxAdjustmentDurationMin, r.DurationMinutes)
	}
	return nil
}

// PriceAdjustmentResponse is the HTTP response for adjust/clear actions.
type PriceAdjustmentResponse struct {
	Success   bool    `json:"success"`
	Pct       float64 `json:"pct"`
	ExpiresAt int64   `json:"expires_at"`
	SetAt     int64   `json:"set_at"`
	Active    bool    `json:"active"`
	Message   string  `json:"message"`
}

// PriceSnapshot is the content of the shared kind-10000 price-snapshot event.
// Field shape matches @ducat-unit/core's PriceQuote interface — wallets read
// rate_min/rate_max/rate_thold/step_size to know how to align a target
// threshold to the rate ladder, so they cannot be omitted.
//
// CRE consensus_aggregation tags are required because this type is returned
// from a cre.ConsensusAggregationFromTags[*PriceSnapshot]() call in the ladder
// workers. All fields use "identical" because every DON node reads the same
// relay event and must agree on its content byte-for-byte.
type PriceSnapshot struct {
	BasePrice    int64   `json:"base_price"     consensus_aggregation:"identical"`
	BaseStamp    int64   `json:"base_stamp"     consensus_aggregation:"identical"`
	ChainNetwork string  `json:"chain_network"  consensus_aggregation:"identical"`
	OraclePubkey string  `json:"oracle_pubkey"  consensus_aggregation:"identical"`
	RateMin      float64 `json:"rate_min"       consensus_aggregation:"identical"`
	RateMax      float64 `json:"rate_max"       consensus_aggregation:"identical"`
	RateThold    float64 `json:"rate_thold"     consensus_aggregation:"identical"`
	StepSize     float64 `json:"step_size"      consensus_aggregation:"identical"`
}

// PriceAdjustmentControl is the content stored in the Nostr control event
type PriceAdjustmentControl struct {
	Pct       float64 `json:"pct"`
	ExpiresAt int64   `json:"expires_at"`
	SetAt     int64   `json:"set_at"`
}

func (a *PriceAdjustmentControl) IsActive(currentTime int64) bool {
	return a != nil && a.Pct != 0 && currentTime < a.ExpiresAt
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
