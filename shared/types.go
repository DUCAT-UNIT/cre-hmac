package shared

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/url"
	"strings"
)

// Config holds workflow configuration (non-sensitive values only)
type Config struct {
	ClientID      string `json:"client_id"`
	DataStreamURL string `json:"data_stream_url"`
	FeedID        string `json:"feed_id"`
	RelayURL      string `json:"relay_url"`
	Network       string `json:"network"`
	// DeploymentNonce is operational metadata used to force an intentional
	// config revision. Keeping it explicit prevents strict parsing from silently
	// discarding a field present in deployed configuration files.
	DeploymentNonce string `json:"deployment_nonce,omitempty"`

	// SECURITY: Authorized Ethereum address for HTTP trigger authentication
	// This MUST be set in production - requests will only be accepted from this address
	// Format: "0x" + 40 hex chars (e.g., "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82")
	AuthorizedKey string `json:"authorized_key"`

	// Cron-based quote generation settings
	CronSchedule         string  `json:"cron_schedule,omitempty"`          // Cron expression (e.g., "0 */5 * * * *" for every 5 minutes)
	RateMin              float64 `json:"rate_min,omitempty"`               // Minimum collateral rate (e.g., 1.35 for 135%)
	RateMax              float64 `json:"rate_max,omitempty"`               // Maximum collateral rate (e.g., 5.00 for 500%)
	StepSize             float64 `json:"step_size,omitempty"`              // Step increment (e.g., 0.05 for 5%)
	LiquidationThold     float64 `json:"liquidation_thold,omitempty"`      // Liquidation threshold (e.g., 1.35 for 135% min collateral)
	QuoteDomain          string  `json:"quote_domain,omitempty"`           // Domain prefix for generated quotes
	RegulatorCallbackURL string  `json:"regulator_callback_url,omitempty"` // Regulator URL for batch completion notifications

	// WorkflowMode selects what the cron handler does.
	//   "price_publisher" → fetches Chainlink + publishes shared kind-10000 snapshot, no ladder.
	//   "ladder" (default, also empty) → reads snapshot from relay + publishes kind-30000 ladder.
	WorkflowMode string `json:"workflow_mode,omitempty"`

	// SECURITY (H1): Chainlink Data Streams report verification.
	//
	// The price fetched from Chainlink Data Streams arrives as a signed
	// "fullReport". Previously the code blindly decoded the price out of the
	// report WITHOUT checking the DON signatures, so a forged/tampered report
	// could inject an arbitrary price into the money path. These fields turn on
	// real verification: the recovered DON signer addresses must all be members
	// of ReportSigners, with at least ReportSignerThreshold distinct signers.
	//
	// The authorized signer set + fault tolerance f live ON-CHAIN for each
	// configDigest and ROTATE; they are not in the payload, so operators must
	// populate ReportSigners out-of-band. Verification is gated behind
	// RequireReportVerification, but Config.Validate permits disabling it only
	// for a loopback DataStreamURL:
	//   - RequireReportVerification == true  and ReportSigners empty => hard
	//     error (fail closed; never silently skip).
	//   - RequireReportVerification == true  with signers => full verification,
	//     reject on any failure.
	//   - RequireReportVerification == false => loopback development only.
	//
	// ReportSigners are lowercased 0x-prefixed 20-byte Ethereum addresses.
	ReportSigners             []string `json:"report_signers,omitempty"`
	ReportSignerThreshold     int      `json:"report_signer_threshold,omitempty"`
	RequireReportVerification bool     `json:"require_report_verification,omitempty"`
}

// UnmarshalJSON rejects unknown configuration fields. Configuration is a
// security boundary: accepting a misspelled field (especially a verification
// toggle) would otherwise silently select its zero value.
func (c *Config) UnmarshalJSON(data []byte) error {
	if err := ValidateNoDuplicateObjectFields(data); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	type plainConfig Config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var decoded plainConfig
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("invalid config: %w", err)
	}
	*c = Config(decoded)
	return nil
}

// ValidateNoDuplicateObjectFields rejects duplicate top-level JSON object
// keys. Go's default decoder otherwise keeps the last value, which creates
// ambiguity when another signer, gateway, or operator tool keeps the first.
func ValidateNoDuplicateObjectFields(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON object: %w", err)
	}
	delim, ok := token.(json.Delim)
	if !ok || delim != '{' {
		return fmt.Errorf("expected JSON object")
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("invalid JSON object key: %w", err)
		}
		key, ok := keyToken.(string)
		if !ok {
			return fmt.Errorf("invalid non-string JSON object key")
		}
		if _, exists := seen[key]; exists {
			return fmt.Errorf("duplicate JSON field %q", key)
		}
		seen[key] = struct{}{}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("invalid value for JSON field %q: %w", key, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("invalid JSON object terminator: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return nil
}

// EffectiveReportSignerThreshold returns the f+1 distinct-signer minimum to
// enforce. If ReportSignerThreshold is set (>=1) it is used as-is. Otherwise it
// defaults to a strict majority of the configured signers
// (floor(n/2)+1), which is a safe default for a DON quorum. Returns 0 when no
// signers are configured.
func (c *Config) EffectiveReportSignerThreshold() int {
	if c.ReportSignerThreshold >= 1 {
		return c.ReportSignerThreshold
	}
	n := len(c.ReportSigners)
	if n == 0 {
		return 0
	}
	return n/2 + 1
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
	// SECURITY: Require TLS for data stream (Chainlink) connections. Parse the
	// URL instead of slicing fixed offsets: malformed/short operator input must
	// return an error, never panic during workflow initialization.
	if err := validateServiceURL(c.DataStreamURL, "data_stream_url", map[string]bool{"https": true}, map[string]bool{"http": true}); err != nil {
		return err
	}
	if c.RelayURL == "" {
		return fmt.Errorf("relay_url required")
	}
	// SECURITY: Require TLS for relay connections in production; ws/http are
	// accepted only for an explicit loopback development endpoint.
	if err := validateServiceURL(c.RelayURL, "relay_url", map[string]bool{"wss": true, "https": true}, map[string]bool{"ws": true, "http": true}); err != nil {
		return err
	}
	if c.FeedID == "" {
		return fmt.Errorf("feed_id required")
	}
	if c.Network == "" {
		return fmt.Errorf("network required")
	}

	// SECURITY: Validate authorized_key format
	// Must be a valid Ethereum address: "0x" + 40 hex chars
	if c.AuthorizedKey == "" {
		return fmt.Errorf("authorized_key required for HTTP trigger authentication")
	}
	if len(c.AuthorizedKey) != 42 {
		return fmt.Errorf("authorized_key must be 42 characters (0x + 40 hex), got %d", len(c.AuthorizedKey))
	}
	if c.AuthorizedKey[:2] != "0x" {
		return fmt.Errorf("authorized_key must start with '0x'")
	}
	// Validate hex characters
	for i, char := range c.AuthorizedKey[2:] {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
			return fmt.Errorf("authorized_key contains invalid hex character at position %d", i+2)
		}
	}

	// SECURITY (H1): Validate Chainlink report verification config.
	if err := c.validateReportVerification(); err != nil {
		return err
	}

	// Validate cron-related fields if any are set
	if c.CronSchedule != "" || c.RateMin != 0 || c.RateMax != 0 || c.StepSize != 0 {
		if err := c.ValidateCronConfig(); err != nil {
			return err
		}
	}

	// SECURITY (M4): validate the regulator callback URL when configured to
	// guard against SSRF / exfiltration to internal endpoints.
	if c.RegulatorCallbackURL != "" {
		if err := ValidateCallbackURL(c.RegulatorCallbackURL); err != nil {
			return fmt.Errorf("regulator_callback_url: %w", err)
		}
	}

	return nil
}

// validateServiceURL validates an absolute service endpoint. secureSchemes are
// accepted for any host; localSchemes are accepted only for localhost or a
// loopback IP. Userinfo is forbidden so credentials cannot be embedded in a
// configured URL and then leaked through routine endpoint logging.
func validateServiceURL(raw, field string, secureSchemes, localSchemes map[string]bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if u.Scheme == "" || u.Host == "" || u.Hostname() == "" {
		return fmt.Errorf("%s must be an absolute URL with a host", field)
	}
	if u.User != nil {
		return fmt.Errorf("%s must not contain userinfo", field)
	}

	if secureSchemes[u.Scheme] {
		return nil
	}
	if localSchemes[u.Scheme] {
		if isLoopbackHost(u.Hostname()) {
			return nil
		}
		if field == "data_stream_url" {
			return fmt.Errorf("data_stream_url must use https:// for non-localhost connections")
		}
		return fmt.Errorf("relay_url must use TLS (wss:// or https://) for non-localhost connections")
	}

	if field == "data_stream_url" {
		return fmt.Errorf("data_stream_url must start with https://")
	}
	return fmt.Errorf("relay_url must start with wss://, https://, ws://, or http://")
}

func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// validateReportVerification validates the Chainlink Data Streams report
// verification configuration (ReportSigners / ReportSignerThreshold /
// RequireReportVerification).
//
// Rules:
//   - Every configured signer must be a valid "0x" + 40 hex char address.
//   - ReportSignerThreshold, if set, must be >= 1.
//   - When RequireReportVerification is true: there must be at least one signer,
//     a positive effective threshold, and enough signers to meet that threshold
//     (len(signers) >= threshold). This is the fail-closed posture.
func (c *Config) validateReportVerification() error {
	seen := make(map[string]int, len(c.ReportSigners))
	for i, s := range c.ReportSigners {
		addr := s
		if len(addr) >= 2 && (addr[:2] == "0x" || addr[:2] == "0X") {
			addr = addr[2:]
		}
		if len(addr) != 40 {
			return fmt.Errorf("report_signers[%d] must be a 0x-prefixed 20-byte hex address, got %q", i, s)
		}
		for j, char := range addr {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f') || (char >= 'A' && char <= 'F')) {
				return fmt.Errorf("report_signers[%d] contains invalid hex character at position %d", i, j)
			}
		}
		canonical := strings.ToLower(addr)
		if first, ok := seen[canonical]; ok {
			return fmt.Errorf("report_signers[%d] duplicates report_signers[%d]", i, first)
		}
		seen[canonical] = i
	}

	if c.ReportSignerThreshold < 0 {
		return fmt.Errorf("report_signer_threshold must not be negative, got %d", c.ReportSignerThreshold)
	}
	if !c.RequireReportVerification {
		u, err := url.Parse(c.DataStreamURL)
		if err != nil || !isLoopbackHost(u.Hostname()) {
			return fmt.Errorf("require_report_verification must be true for non-loopback data_stream_url")
		}
		if len(c.ReportSigners) != 0 || c.ReportSignerThreshold != 0 {
			return fmt.Errorf("report signer settings require require_report_verification=true")
		}
		return nil
	}

	if len(c.ReportSigners) == 0 {
		return fmt.Errorf("require_report_verification is true but report_signers is empty: cannot verify reports fail-closed")
	}
	threshold := c.EffectiveReportSignerThreshold()
	if threshold < 1 {
		return fmt.Errorf("require_report_verification is true but effective report_signer_threshold is %d (must be >= 1)", threshold)
	}
	if len(c.ReportSigners) < threshold {
		return fmt.Errorf("require_report_verification is true but report_signers has %d entries < threshold %d", len(c.ReportSigners), threshold)
	}

	return nil
}

// ValidateCronConfig validates cron-related configuration fields
func (c *Config) ValidateCronConfig() error {
	if c.CronSchedule == "" && (c.RateMin != 0 || c.RateMax != 0 || c.StepSize != 0) {
		return fmt.Errorf("cron_schedule required when rate parameters are set")
	}
	// price_publisher and promoter modes do not generate ladders, so rate
	// params are not required even though cron_schedule is set.
	if c.WorkflowMode == "price_publisher" || c.WorkflowMode == "promoter" {
		return nil
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
		liquidationThold := c.LiquidationThold
		if liquidationThold == 0 {
			liquidationThold = 1.35
		}
		if math.IsNaN(liquidationThold) || math.IsInf(liquidationThold, 0) || liquidationThold <= 0 {
			return fmt.Errorf("liquidation_thold must be finite and positive, got %.4f", liquidationThold)
		}
		if liquidationThold >= c.RateMin {
			return fmt.Errorf("liquidation_thold (%.4f) must be less than rate_min (%.4f)", liquidationThold, c.RateMin)
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
		if price > float64(MaxPriceValue) {
			return fmt.Errorf("threshold price exceeds maximum %d, got %.2f", MaxPriceValue, price)
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

	// SECURITY (M4): validate callback URL when present (SSRF/exfil defense).
	if r.CallbackURL != nil && *r.CallbackURL != "" {
		if err := ValidateCallbackURL(*r.CallbackURL); err != nil {
			return fmt.Errorf("callback_url: %w", err)
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
	seen := make(map[string]struct{}, len(r.TholdHashes))
	for i, hash := range r.TholdHashes {
		hashLen := len(hash)
		if hashLen != TholdHashLength && hashLen != CommitHashLength {
			return fmt.Errorf("invalid hash at index %d: expected %d or %d hex chars, got %d", i, TholdHashLength, CommitHashLength, hashLen)
		}
		if !IsValidHex(hash) {
			return fmt.Errorf("invalid hash format at index %d: must be lowercase hex", i)
		}
		if _, exists := seen[hash]; exists {
			return fmt.Errorf("duplicate hash at index %d: %s", i, hash)
		}
		seen[hash] = struct{}{}
	}

	// SECURITY (M4): validate callback URL when present (SSRF/exfil defense).
	if r.CallbackURL != nil && *r.CallbackURL != "" {
		if err := ValidateCallbackURL(*r.CallbackURL); err != nil {
			return fmt.Errorf("callback_url: %w", err)
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

	// SECURITY (M4): validate callback URL when present (SSRF/exfil defense).
	if r.CallbackURL != nil && *r.CallbackURL != "" {
		if err := ValidateCallbackURL(*r.CallbackURL); err != nil {
			return fmt.Errorf("callback_url: %w", err)
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
	TholdHash    string  `json:"thold_hash"`
	Status       string  `json:"status"` // "breached", "active", or "error"
	TholdKey     *string `json:"thold_key"`
	CurrentPrice float64 `json:"current_price"`
	TholdPrice   float64 `json:"thold_price"`
	Error        *string `json:"error,omitempty"`
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

// PriceEvent represents a price threshold event (v2.5 schema)
// Aligned with client-sdk@0.7.23 QuoteTemplate schema.
//
// Price Truncation Behavior:
// Prices are stored as float64 for consistency with TypeScript's number type.
// Float64 prices like 100234.56 are truncated to 100234 when converted to
// uint32 for cryptographic operations (hash preimages, signatures).
// This matches the TypeScript core-ts implementation which uses Buff.num(value, 4) for
// 4-byte big-endian encoding. Fractional cents are intentionally discarded.
type PriceEvent struct {
	// Server identity
	SrvNetwork string `json:"srv_network"` // "main" | "test"
	SrvPubkey  string `json:"srv_pubkey"`  // Oracle public key (hex)

	// Quote price (at commitment creation)
	QuoteOrigin string  `json:"quote_origin"` // "link" | "nostr" | "cre"
	QuotePrice  float64 `json:"quote_price"`  // BTC/USD price
	QuoteStamp  int64   `json:"quote_stamp"`  // Unix timestamp

	// Latest price (most recent observation)
	LatestOrigin string  `json:"latest_origin"`
	LatestPrice  float64 `json:"latest_price"`
	LatestStamp  int64   `json:"latest_stamp"`

	// Event price (at breach, if any)
	EventOrigin *string  `json:"event_origin"`
	EventPrice  *float64 `json:"event_price"`
	EventStamp  *int64   `json:"event_stamp"`
	EventType   string   `json:"event_type"` // "active" | "breach"

	// Threshold commitment
	TholdHash  string  `json:"thold_hash"`  // Hash160 (20 bytes hex)
	TholdKey   *string `json:"thold_key"`   // Revealed on breach
	TholdPrice float64 `json:"thold_price"` // Threshold price

	// State & signatures
	IsExpired bool   `json:"is_expired"`
	ReqID     string `json:"req_id"`  // Request ID hash
	ReqSig    string `json:"req_sig"` // Schnorr signature
}

// IsBreached returns true if the price event represents a breach
func (p *PriceEvent) IsBreached() bool {
	return p.EventType == EventTypeBreach
}

// IsActive returns true if the price event is still active
func (p *PriceEvent) IsActive() bool {
	return p.EventType == EventTypeActive
}

// Validate validates the price event fields (v2.5 schema)
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
	if !IsValidSchnorrPubkey(p.SrvPubkey) {
		return fmt.Errorf("invalid srv_pubkey: %s", p.SrvPubkey)
	}
	if p.SrvNetwork != "main" && p.SrvNetwork != "test" {
		return fmt.Errorf("invalid srv_network: %s (must be 'main' or 'test')", p.SrvNetwork)
	}
	if p.ReqID == "" {
		return fmt.Errorf("req_id required")
	}
	if !IsValidOracleSig(p.ReqSig) {
		return fmt.Errorf("invalid req_sig: %s", p.ReqSig)
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

// HasTagValue reports whether the event contains an exact two-field-or-longer
// tag match. Callers that query an untrusted relay should re-check requested
// filter predicates locally after verifying the event signature.
func (e *NostrEvent) HasTagValue(tagName, value string) bool {
	if e == nil {
		return false
	}
	for _, tag := range e.Tags {
		if len(tag) >= 2 && tag[0] == tagName && tag[1] == value {
			return true
		}
	}
	return false
}

// RelayResponse represents relay operation response
type RelayResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}
