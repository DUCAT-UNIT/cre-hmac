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

// HttpRequestData represents incoming HTTP request
type HttpRequestData struct {
	Domain     string   `json:"domain"`
	TholdPrice *float64 `json:"thold_price,omitempty"`
	TholdHash  *string  `json:"thold_hash,omitempty"`
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
	}

	// Threshold hash validation
	if r.TholdHash != nil {
		hash := *r.TholdHash
		if len(hash) != 40 {
			return fmt.Errorf("invalid thold_hash length: expected 40 hex chars, got %d", len(hash))
		}
		if !isValidHex(hash) {
			return fmt.Errorf("invalid thold_hash format: must be lowercase hex")
		}
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

// isValidHex checks if string is valid lowercase hex
func isValidHex(s string) bool {
	validHex := regexp.MustCompile(`^[0-9a-f]+$`)
	return validHex.MatchString(s)
}

// PriceEvent represents a price threshold event (matches price-oracle structure)
// Core price-oracle fields with DUCAT cryptographic extensions
type PriceEvent struct {
	// Core price event fields (from price-oracle PriceEvent)
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

	// DUCAT cryptographic extensions (from price-oracle EventQuoteTemplate)
	IsExpired  bool    `json:"is_expired"`  // true if threshold breached
	SrvNetwork string  `json:"srv_network"` // Bitcoin network (Mainnet/Testnet/Mutinynet)
	SrvPubkey  string  `json:"srv_pubkey"`  // Server Schnorr public key
	TholdHash  string  `json:"thold_hash"`  // Hash160 commitment
	TholdKey   string  `json:"thold_key"`   // Secret (empty if not breached, populated if breached)
	TholdPrice float64 `json:"thold_price"` // Threshold price
	ReqID      string  `json:"req_id"`      // Deterministic request ID
	ReqSig     string  `json:"req_sig"`     // Schnorr signature of request ID
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
