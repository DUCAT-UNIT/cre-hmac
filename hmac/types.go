//go:build wasip1

package main

import (
	"fmt"
	"math"
	"regexp"

	"github.com/shopspring/decimal"
)

// Config holds workflow configuration (non-sensitive values only)
type Config struct {
	ClientID      string `json:"client_id"`
	DataStreamURL string `json:"data_stream_url"`
	FeedID        string `json:"feed_id"`
	RelayURL      string `json:"relay_url"`
	Network       string `json:"network"`

	// Cron-based quote generation settings
	CronSchedule       string  `json:"cron_schedule,omitempty"`        // Cron expression (e.g., "0 */5 * * * *" for every 5 minutes)
	RateMin            float64 `json:"rate_min,omitempty"`             // Minimum rate (e.g., 1.35 for 135%)
	RateMax            float64 `json:"rate_max,omitempty"`             // Maximum rate (e.g., 5.00 for 500%)
	StepSize           float64 `json:"step_size,omitempty"`            // Step increment (e.g., 0.05 for 5%)
	QuoteDomain        string  `json:"quote_domain,omitempty"`         // Domain prefix for generated quotes
	GatewayCallbackURL string  `json:"gateway_callback_url,omitempty"` // Gateway URL for batch completion notifications
}

// Validate validates the configuration
func (c *Config) Validate() error {
	if c.ClientID == "" {
		return fmt.Errorf("client_id required")
	}
	if c.DataStreamURL == "" || c.RelayURL == "" {
		return fmt.Errorf("URLs required")
	}
	if c.FeedID == "" {
		return fmt.Errorf("feed_id required")
	}
	return nil
}

// PriceData represents Chainlink price data
type PriceData struct {
	Price  decimal.Decimal `json:"price" consensus_aggregation:"median"`
	Origin string          `json:"origin" consensus_aggregation:"identical"`
	Stamp  int64           `json:"stamp" consensus_aggregation:"median"`
}

// HttpRequestData represents incoming HTTP request for creating quotes
type HttpRequestData struct {
	Domain      string   `json:"domain"`
	TholdPrice  *float64 `json:"thold_price"`
	CallbackURL *string  `json:"callback_url,omitempty"` // Optional webhook for result notification
}

// Validate validates request data
func (r *HttpRequestData) Validate() error {
	// Domain validation
	if r.Domain == "" {
		return fmt.Errorf("domain required")
	}
	if len(r.Domain) > MaxDomainLength {
		return fmt.Errorf("domain too long: max %d chars, got %d", MaxDomainLength, len(r.Domain))
	}
	if !isValidDomain(r.Domain) {
		return fmt.Errorf("domain contains invalid characters (only alphanumeric, dots, hyphens, underscores allowed)")
	}

	// Threshold price validation
	if r.TholdPrice == nil {
		return fmt.Errorf("thold_price required")
	}

	price := *r.TholdPrice
	// Check for NaN
	if price != price {
		return fmt.Errorf("threshold price is NaN")
	}
	// Check for infinity
	if math.IsInf(price, 0) {
		return fmt.Errorf("threshold price is infinite")
	}
	// Check bounds
	if price <= 0 {
		return fmt.Errorf("threshold price must be positive, got %.2f", price)
	}
	if price > MaxPriceValue {
		return fmt.Errorf("threshold price exceeds maximum %.0f, got %.2f", MaxPriceValue, price)
	}

	return nil
}

// isValidDomain checks if domain contains only allowed characters
// Allows: alphanumeric, dots, hyphens, underscores
// This prevents injection attacks and ensures domain is safe for use in HMAC
func isValidDomain(domain string) bool {
	// Pattern: alphanumeric, dots, hyphens, underscores only
	// No spaces, no special chars, no control characters
	validDomain := regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	return validDomain.MatchString(domain)
}

// isValidHex reports whether s contains only lowercase hexadecimal characters (0-9, a-f).
func isValidHex(s string) bool {
	validHex := regexp.MustCompile(`^[0-9a-f]+$`)
	return validHex.MatchString(s)
}

// PriceEvent represents a price threshold event
// Aligned with core-ts PriceContract schema for client-sdk compatibility
type PriceEvent struct {
	// Core price event fields
	EventOrigin  *string  `json:"event_origin"`   // nullable - null if not breached
	EventPrice   *float64 `json:"event_price"`    // nullable - null if not breached
	EventStamp   *int64   `json:"event_stamp"`    // nullable - null if not breached
	EventType    string   `json:"event_type"`     // "active" or "breach"
	LatestOrigin string   `json:"latest_origin"`  // current price origin
	LatestPrice  float64  `json:"latest_price"`   // current price
	LatestStamp  int64    `json:"latest_stamp"`   // current timestamp
	QuoteOrigin  string   `json:"quote_origin"`   // quote creation origin
	QuotePrice   float64  `json:"quote_price"`    // quote creation price
	QuoteStamp   int64    `json:"quote_stamp"`    // quote creation timestamp

	// Core-ts PriceContract fields (for client-sdk compatibility)
	ChainNetwork string  `json:"chain_network"` // Bitcoin network (maps to srv_network)
	OraclePubkey string  `json:"oracle_pubkey"` // Server Schnorr public key (maps to srv_pubkey)
	BasePrice    int64   `json:"base_price"`    // Quote creation price as int
	BaseStamp    int64   `json:"base_stamp"`    // Quote creation timestamp
	CommitHash   string  `json:"commit_hash"`   // hash340(tag, preimage) - 32 bytes hex
	ContractID   string  `json:"contract_id"`   // hash340(tag, commit||thold) - 32 bytes hex
	OracleSig    string  `json:"oracle_sig"`    // Schnorr signature - 64 bytes hex
	TholdHash    string  `json:"thold_hash"`    // Hash160 commitment - 20 bytes hex
	TholdKey     *string `json:"thold_key"`     // Secret (null if not breached) - 32 bytes hex
	TholdPrice   float64 `json:"thold_price"`   // Threshold price

	// Legacy fields (kept for backwards compatibility during transition)
	IsExpired  bool   `json:"is_expired"`  // true if threshold breached
	SrvNetwork string `json:"srv_network"` // Bitcoin network (legacy name)
	SrvPubkey  string `json:"srv_pubkey"`  // Server Schnorr public key (legacy name)
	ReqID      string `json:"req_id"`      // Same as contract_id (legacy name)
	ReqSig     string `json:"req_sig"`     // Same as oracle_sig (legacy name)
}

// NostrEvent represents a Nostr NIP-01 event
type NostrEvent struct {
	ID        string     `json:"id"`
	PubKey    string     `json:"pubkey"`
	CreatedAt int64      `json:"created_at"`
	Kind      int        `json:"kind"`
	Tags      [][]string `json:"tags"`
	Content   string     `json:"content"`
	Sig       string     `json:"sig"`
}

// RelayResponse represents relay operation response
type RelayResponse struct {
	Success bool   `json:"success" consensus_aggregation:"identical"`
	Message string `json:"message" consensus_aggregation:"identical"`
}

// KeyDerivation holds derived cryptographic keys
type KeyDerivation struct {
	PrivateKey    []byte
	SchnorrPubkey string
}

// =============================================================================
// Evaluate Quotes Types (Batch evaluation of quotes by thold_hash)
// =============================================================================

// EvaluateQuotesRequest represents batch quote evaluation request
type EvaluateQuotesRequest struct {
	TholdHashes []string `json:"thold_hashes"`          // List of thold_hash values to evaluate
	CallbackURL *string  `json:"callback_url,omitempty"` // Optional webhook callback
}

// Validate validates the evaluate quotes request
func (r *EvaluateQuotesRequest) Validate() error {
	if len(r.TholdHashes) == 0 {
		return fmt.Errorf("thold_hashes required: at least one thold_hash must be provided")
	}
	if len(r.TholdHashes) > 100 {
		return fmt.Errorf("too many thold_hashes: max 100, got %d", len(r.TholdHashes))
	}
	for i, hash := range r.TholdHashes {
		if len(hash) != 40 {
			return fmt.Errorf("invalid thold_hash at index %d: expected 40 hex chars, got %d", i, len(hash))
		}
		if !isValidHex(hash) {
			return fmt.Errorf("invalid thold_hash format at index %d: must be lowercase hex", i)
		}
	}
	return nil
}

// QuoteEvaluationResult represents result for a single quote evaluation
type QuoteEvaluationResult struct {
	TholdHash    string   `json:"thold_hash"`              // The threshold hash that was evaluated
	Status       string   `json:"status"`                  // "breached" or "active"
	TholdKey     *string  `json:"thold_key"`               // Revealed secret if breached, null if active
	CurrentPrice float64  `json:"current_price"`           // Current BTC/USD price at evaluation time
	TholdPrice   float64  `json:"thold_price"`             // Threshold price for this quote
	Error        *string  `json:"error,omitempty"`         // Error message if evaluation failed
}

// EvaluateQuotesResponse represents batch evaluation response
type EvaluateQuotesResponse struct {
	Results      []QuoteEvaluationResult `json:"results"`         // Results for each thold_hash
	CurrentPrice float64                 `json:"current_price"`   // Current BTC/USD price used for all evaluations
	EvaluatedAt  int64                   `json:"evaluated_at"`    // Timestamp of evaluation
	Summary      *EvaluationSummary      `json:"summary,omitempty"` // Aggregated statistics
}

// EvaluationSummary provides aggregated statistics for batch evaluation
type EvaluationSummary struct {
	Total     int      `json:"total"`
	Breached  int      `json:"breached"`
	Active    int      `json:"active"`
	Errors    int      `json:"errors"`
	ErrorMsgs []string `json:"error_messages,omitempty"`
}

// ComputeSummary computes and sets the summary field from results
func (r *EvaluateQuotesResponse) ComputeSummary() {
	summary := &EvaluationSummary{
		Total: len(r.Results),
	}
	for _, result := range r.Results {
		switch result.Status {
		case "breached":
			summary.Breached++
		case "active":
			summary.Active++
		case "error":
			summary.Errors++
			if result.Error != nil {
				summary.ErrorMsgs = append(summary.ErrorMsgs, *result.Error)
			}
		}
	}
	r.Summary = summary
}

// =============================================================================
// Generate Quotes Types (Auto-generate quotes at price intervals)
// =============================================================================

// GenerateQuotesRequest represents auto-generation request
type GenerateQuotesRequest struct {
	RateMin     float64 `json:"rate_min"`              // Minimum rate (e.g., 1.35 for 135%)
	RateMax     float64 `json:"rate_max"`              // Maximum rate (e.g., 5.00 for 500%)
	StepSize    float64 `json:"step_size"`             // Step increment (e.g., 0.05 for 5%)
	Domain      string  `json:"domain"`                // Tracking domain for callback
	QuoteDomain string  `json:"quote_domain"`          // Domain prefix for generated quotes (optional, defaults to Domain)
	CallbackURL *string `json:"callback_url,omitempty"` // Optional webhook callback
}

// Validate validates the generate quotes request
func (r *GenerateQuotesRequest) Validate() error {
	// Rate validation
	if r.RateMin <= 0 {
		return fmt.Errorf("rate_min must be positive, got %.4f", r.RateMin)
	}
	if r.RateMax <= 0 {
		return fmt.Errorf("rate_max must be positive, got %.4f", r.RateMax)
	}
	if r.RateMin >= r.RateMax {
		return fmt.Errorf("rate_min (%.4f) must be less than rate_max (%.4f)", r.RateMin, r.RateMax)
	}
	if r.RateMin < 1.01 {
		return fmt.Errorf("rate_min must be at least 1.01 (1%% above current), got %.4f", r.RateMin)
	}

	// Step size validation
	if r.StepSize <= 0 {
		return fmt.Errorf("step_size must be positive, got %.4f", r.StepSize)
	}
	if r.StepSize < 0.01 {
		return fmt.Errorf("step_size must be at least 0.01 (1%%), got %.4f", r.StepSize)
	}
	if r.StepSize > 1.0 {
		return fmt.Errorf("step_size must not exceed 1.0 (100%%), got %.4f", r.StepSize)
	}

	// Calculate number of quotes to prevent excessive generation
	// Use math.Round to avoid floating-point rounding errors (e.g., 3.65/0.01 = 364.99999...)
	numQuotes := int(math.Round((r.RateMax-r.RateMin)/r.StepSize)) + 1
	if numQuotes > 1000 {
		return fmt.Errorf("too many quotes would be generated (%d), reduce range or increase step_size", numQuotes)
	}

	// Domain validation
	if r.Domain == "" {
		return fmt.Errorf("domain required")
	}
	if len(r.Domain) > MaxDomainLength-20 { // Leave room for suffix
		return fmt.Errorf("domain too long: max %d chars, got %d", MaxDomainLength-20, len(r.Domain))
	}
	if !isValidDomain(r.Domain) {
		return fmt.Errorf("domain contains invalid characters")
	}

	// QuoteDomain validation (optional, defaults to Domain)
	if r.QuoteDomain != "" {
		if len(r.QuoteDomain) > MaxDomainLength-20 {
			return fmt.Errorf("quote_domain too long: max %d chars, got %d", MaxDomainLength-20, len(r.QuoteDomain))
		}
		if !isValidDomain(r.QuoteDomain) {
			return fmt.Errorf("quote_domain contains invalid characters")
		}
	}

	return nil
}

// GenerateQuotesResponse represents auto-generation response
type GenerateQuotesResponse struct {
	QuotesCreated int      `json:"quotes_created"`  // Number of quotes created
	CurrentPrice  float64  `json:"current_price"`   // Current BTC/USD price used
	Range         struct {
		MinThold float64 `json:"min_thold"` // Lowest threshold price
		MaxThold float64 `json:"max_thold"` // Highest threshold price
	} `json:"range"`
	TholdHashes []string `json:"thold_hashes"`    // List of created thold_hash values
	GeneratedAt int64    `json:"generated_at"`    // Timestamp of generation
}

// BatchGeneratedInfo is sent to gateway after batch quote generation
// Gateway caches this to serve the current base price to clients
type BatchGeneratedInfo struct {
	BasePrice int64 `json:"base_price"` // BTC/USD price used for this batch
	BaseStamp int64 `json:"base_stamp"` // Timestamp when batch was generated
}

// PriceContractResponse matches core-ts PriceContract schema exactly
// This is the format sent to the gateway - no transformation needed
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

// ToPriceContractResponse converts PriceEvent to PriceContractResponse
func (p *PriceEvent) ToPriceContractResponse() *PriceContractResponse {
	return &PriceContractResponse{
		ChainNetwork: p.ChainNetwork,
		OraclePubkey: p.OraclePubkey,
		BasePrice:    p.BasePrice,
		BaseStamp:    p.BaseStamp,
		CommitHash:   p.CommitHash,
		ContractID:   p.ContractID,
		OracleSig:    p.OracleSig,
		TholdHash:    p.TholdHash,
		TholdKey:     p.TholdKey,
		TholdPrice:   int64(p.TholdPrice),
	}
}