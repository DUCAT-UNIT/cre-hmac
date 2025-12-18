package shared

import (
	"fmt"
	"math"
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
	if c == nil {
		return fmt.Errorf("config is nil")
	}
	if c.ClientID == "" {
		return fmt.Errorf("client_id required")
	}
	if c.DataStreamURL == "" {
		return fmt.Errorf("data_stream_url required")
	}
	if c.RelayURL == "" {
		return fmt.Errorf("relay_url required")
	}
	if c.FeedID == "" {
		return fmt.Errorf("feed_id required")
	}
	if c.Network == "" {
		return fmt.Errorf("network required")
	}

	// Validate cron-related fields if any are set
	if c.CronSchedule != "" || c.RateMin != 0 || c.RateMax != 0 || c.StepSize != 0 {
		if err := c.ValidateCronConfig(); err != nil {
			return err
		}
	}

	return nil
}

// ValidateCronConfig validates cron-related configuration fields
func (c *Config) ValidateCronConfig() error {
	if c.CronSchedule == "" && (c.RateMin != 0 || c.RateMax != 0 || c.StepSize != 0) {
		return fmt.Errorf("cron_schedule required when rate parameters are set")
	}
	if c.CronSchedule != "" {
		if c.RateMin <= 0 {
			return fmt.Errorf("rate_min must be positive when cron_schedule is set, got %.4f", c.RateMin)
		}
		if c.RateMax <= 0 {
			return fmt.Errorf("rate_max must be positive when cron_schedule is set, got %.4f", c.RateMax)
		}
		if c.StepSize <= 0 {
			return fmt.Errorf("step_size must be positive when cron_schedule is set, got %.4f", c.StepSize)
		}
		if c.RateMin >= c.RateMax {
			return fmt.Errorf("rate_min (%.4f) must be less than rate_max (%.4f)", c.RateMin, c.RateMax)
		}
		if c.RateMin < 1.01 {
			return fmt.Errorf("rate_min must be at least 1.01 (1%% above current), got %.4f", c.RateMin)
		}
	}
	return nil
}

// HttpRequestData represents incoming HTTP request for create/check operations
type HttpRequestData struct {
	Domain      string   `json:"domain"`
	TholdPrice  *float64 `json:"thold_price,omitempty"`
	TholdHash   *string  `json:"thold_hash,omitempty"`
	CallbackURL *string  `json:"callback_url,omitempty"`
}

// Validate validates request data
func (r *HttpRequestData) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}

	// Domain validation
	if err := ValidateDomain(r.Domain); err != nil {
		return err
	}

	// Request type validation
	if r.TholdPrice == nil && r.TholdHash == nil {
		return fmt.Errorf("either thold_price or thold_hash required")
	}
	if r.TholdPrice != nil && r.TholdHash != nil {
		return fmt.Errorf("cannot specify both thold_price and thold_hash")
	}

	// Threshold price validation
	if r.TholdPrice != nil {
		price := *r.TholdPrice
		// Check for NaN
		if math.IsNaN(price) {
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
	}

	// Threshold hash validation
	if r.TholdHash != nil {
		hash := *r.TholdHash
		if len(hash) != TholdHashLength {
			return fmt.Errorf("invalid thold_hash length: expected %d hex chars, got %d", TholdHashLength, len(hash))
		}
		if !IsValidHex(hash) {
			return fmt.Errorf("invalid thold_hash format: must be lowercase hex")
		}
	}

	return nil
}

// IsCreateRequest returns true if this is a create quote request
func (r *HttpRequestData) IsCreateRequest() bool {
	return r.TholdPrice != nil
}

// IsCheckRequest returns true if this is a check quote request
func (r *HttpRequestData) IsCheckRequest() bool {
	return r.TholdHash != nil
}

// EvaluateQuotesRequest represents batch quote evaluation request
type EvaluateQuotesRequest struct {
	TholdHashes []string `json:"thold_hashes"`
	CallbackURL *string  `json:"callback_url,omitempty"`
}

// Validate validates the evaluate quotes request.
// It enforces MaxBatchSize to limit the number of concurrent external requests.
func (r *EvaluateQuotesRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}
	if len(r.TholdHashes) == 0 {
		return fmt.Errorf("thold_hashes required: at least one thold_hash must be provided")
	}
	if len(r.TholdHashes) > MaxBatchSize {
		return fmt.Errorf("too many thold_hashes: max %d, got %d", MaxBatchSize, len(r.TholdHashes))
	}
	for i, hash := range r.TholdHashes {
		if len(hash) != TholdHashLength {
			return fmt.Errorf("invalid thold_hash at index %d: expected %d hex chars, got %d", i, TholdHashLength, len(hash))
		}
		if !IsValidHex(hash) {
			return fmt.Errorf("invalid thold_hash format at index %d: must be lowercase hex", i)
		}
	}
	return nil
}

// GenerateQuotesRequest represents auto-generation request
type GenerateQuotesRequest struct {
	RateMin     float64 `json:"rate_min"`
	RateMax     float64 `json:"rate_max"`
	StepSize    float64 `json:"step_size"`
	Domain      string  `json:"domain"`
	QuoteDomain string  `json:"quote_domain"`
	CallbackURL *string `json:"callback_url,omitempty"`
}

// Validate validates the generate quotes request
func (r *GenerateQuotesRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}

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
	numQuotes := r.CalculateNumQuotes()
	if numQuotes > 1000 {
		return fmt.Errorf("too many quotes would be generated (%d), reduce range or increase step_size", numQuotes)
	}

	// Domain validation
	if err := ValidateDomainWithSuffix(r.Domain, 20); err != nil {
		return err
	}

	// QuoteDomain validation (optional, defaults to Domain)
	if r.QuoteDomain != "" {
		if err := ValidateDomainWithSuffix(r.QuoteDomain, 20); err != nil {
			return fmt.Errorf("quote_domain: %w", err)
		}
	}

	return nil
}

// CalculateNumQuotes calculates the number of quotes that would be generated
func (r *GenerateQuotesRequest) CalculateNumQuotes() int {
	if r.StepSize <= 0 {
		return 0
	}
	return int((r.RateMax-r.RateMin)/r.StepSize) + 1
}

// GetQuoteDomain returns the quote domain (defaults to Domain if not set)
func (r *GenerateQuotesRequest) GetQuoteDomain() string {
	if r.QuoteDomain != "" {
		return r.QuoteDomain
	}
	return r.Domain
}

// QuoteEvaluationResult represents result for a single quote evaluation
type QuoteEvaluationResult struct {
	TholdHash    string   `json:"thold_hash"`
	Status       string   `json:"status"` // "breached", "active", or "error"
	TholdKey     *string  `json:"thold_key"`
	CurrentPrice float64  `json:"current_price"`
	TholdPrice   float64  `json:"thold_price"`
	Error        *string  `json:"error,omitempty"`
}

// IsBreached returns true if the quote was breached
func (r *QuoteEvaluationResult) IsBreached() bool {
	return r.Status == "breached"
}

// IsActive returns true if the quote is still active
func (r *QuoteEvaluationResult) IsActive() bool {
	return r.Status == "active"
}

// IsError returns true if there was an error evaluating the quote
func (r *QuoteEvaluationResult) IsError() bool {
	return r.Status == "error"
}

// EvaluateQuotesResponse represents batch evaluation response
type EvaluateQuotesResponse struct {
	Results      []QuoteEvaluationResult `json:"results"`
	CurrentPrice float64                 `json:"current_price"`
	EvaluatedAt  int64                   `json:"evaluated_at"`
	Summary      *EvaluationSummary      `json:"summary,omitempty"`
}

// EvaluationSummary provides aggregated statistics for batch evaluation
type EvaluationSummary struct {
	Total    int      `json:"total"`
	Breached int      `json:"breached"`
	Active   int      `json:"active"`
	Errors   int      `json:"errors"`
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

// GetErrors returns all error messages from the results
func (r *EvaluateQuotesResponse) GetErrors() []string {
	var errors []string
	for _, result := range r.Results {
		if result.IsError() && result.Error != nil {
			errors = append(errors, *result.Error)
		}
	}
	return errors
}

// CountBreached returns the number of breached quotes
func (r *EvaluateQuotesResponse) CountBreached() int {
	count := 0
	for _, result := range r.Results {
		if result.IsBreached() {
			count++
		}
	}
	return count
}

// CountActive returns the number of active quotes
func (r *EvaluateQuotesResponse) CountActive() int {
	count := 0
	for _, result := range r.Results {
		if result.IsActive() {
			count++
		}
	}
	return count
}

// CountErrors returns the number of error results
func (r *EvaluateQuotesResponse) CountErrors() int {
	count := 0
	for _, result := range r.Results {
		if result.IsError() {
			count++
		}
	}
	return count
}

// GenerateQuotesResponse represents auto-generation response
type GenerateQuotesResponse struct {
	QuotesCreated int     `json:"quotes_created"`
	CurrentPrice  float64 `json:"current_price"`
	Range         struct {
		MinThold float64 `json:"min_thold"`
		MaxThold float64 `json:"max_thold"`
	} `json:"range"`
	TholdHashes []string `json:"thold_hashes"`
	GeneratedAt int64    `json:"generated_at"`
}

// PriceEvent represents a price threshold event
// Aligned with core-ts PriceContract schema for client-sdk compatibility.
//
// Price Truncation Behavior:
// Prices are stored as int64 (BasePrice) for consistency with TypeScript's number type
// and for deterministic hashing. Float64 prices like 100234.56 are truncated to 100234
// when converted to uint32 for cryptographic operations (hash preimages, signatures).
// This matches the TypeScript core-ts implementation which uses Buff.num(value, 4) for
// 4-byte big-endian encoding. Fractional cents are intentionally discarded.
type PriceEvent struct {
	// Core price event fields
	EventOrigin  *string  `json:"event_origin"`
	EventPrice   *float64 `json:"event_price"`
	EventStamp   *int64   `json:"event_stamp"`
	EventType    string   `json:"event_type"`
	LatestOrigin string   `json:"latest_origin"`
	LatestPrice  float64  `json:"latest_price"`
	LatestStamp  int64    `json:"latest_stamp"`
	QuoteOrigin  string   `json:"quote_origin"`
	QuotePrice   float64  `json:"quote_price"`
	QuoteStamp   int64    `json:"quote_stamp"`

	// Core-ts PriceContract fields (for client-sdk compatibility)
	ChainNetwork string  `json:"chain_network"`
	OraclePubkey string  `json:"oracle_pubkey"`
	BasePrice    int64   `json:"base_price"`
	BaseStamp    int64   `json:"base_stamp"`
	CommitHash   string  `json:"commit_hash"`
	ContractID   string  `json:"contract_id"`
	OracleSig    string  `json:"oracle_sig"`
	TholdHash    string  `json:"thold_hash"`
	TholdKey     *string `json:"thold_key"`
	TholdPrice   float64 `json:"thold_price"`

	// Legacy fields (kept for backwards compatibility during transition)
	IsExpired  bool   `json:"is_expired"`
	SrvNetwork string `json:"srv_network"`
	SrvPubkey  string `json:"srv_pubkey"`
	ReqID      string `json:"req_id"`
	ReqSig     string `json:"req_sig"`
}

// IsBreached returns true if the price event represents a breach
func (p *PriceEvent) IsBreached() bool {
	return p.EventType == EventTypeBreach
}

// IsActive returns true if the price event is still active
func (p *PriceEvent) IsActive() bool {
	return p.EventType == EventTypeActive
}

// Validate validates the price event fields
func (p *PriceEvent) Validate() error {
	if p == nil {
		return fmt.Errorf("price event is nil")
	}
	if p.EventType != EventTypeActive && p.EventType != EventTypeBreach {
		return fmt.Errorf("invalid event_type: %s (must be '%s' or '%s')", p.EventType, EventTypeActive, EventTypeBreach)
	}
	if !IsValidTholdHash(p.TholdHash) {
		return fmt.Errorf("invalid thold_hash: %s", p.TholdHash)
	}
	if !IsValidCommitHash(p.CommitHash) {
		return fmt.Errorf("invalid commit_hash: %s", p.CommitHash)
	}
	if !IsValidContractID(p.ContractID) {
		return fmt.Errorf("invalid contract_id: %s", p.ContractID)
	}
	if !IsValidOracleSig(p.OracleSig) {
		return fmt.Errorf("invalid oracle_sig: %s", p.OracleSig)
	}
	if !IsValidSchnorrPubkey(p.OraclePubkey) {
		return fmt.Errorf("invalid oracle_pubkey: %s", p.OraclePubkey)
	}
	if p.IsBreached() && p.TholdKey == nil {
		return fmt.Errorf("breached event must have thold_key")
	}
	if p.TholdKey != nil && !IsValidTholdKey(*p.TholdKey) {
		return fmt.Errorf("invalid thold_key: %s", *p.TholdKey)
	}
	return nil
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

// GetTag returns the first value for a tag, or empty string if not found
func (e *NostrEvent) GetTag(tagName string) string {
	for _, tag := range e.Tags {
		if len(tag) >= 2 && tag[0] == tagName {
			return tag[1]
		}
	}
	return ""
}

// GetAllTagValues returns all values for a tag
func (e *NostrEvent) GetAllTagValues(tagName string) []string {
	var values []string
	for _, tag := range e.Tags {
		if len(tag) >= 2 && tag[0] == tagName {
			values = append(values, tag[1])
		}
	}
	return values
}

// RelayResponse represents relay operation response
type RelayResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
