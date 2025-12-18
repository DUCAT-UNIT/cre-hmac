package shared

import (
	"fmt"
	"math"
	"regexp"
)

// Compiled regexes for validation (compiled once for performance)
var (
	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	validHexRegex    = regexp.MustCompile(`^[0-9a-f]+$`)
)

// IsValidDomain checks if domain contains only allowed characters
// Allows: alphanumeric, dots, hyphens, underscores
// This prevents injection attacks and ensures domain is safe for use in HMAC
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return validDomainRegex.MatchString(domain)
}

// IsValidHex checks if string is valid lowercase hex
func IsValidHex(s string) bool {
	if s == "" {
		return false
	}
	return validHexRegex.MatchString(s)
}

// IsValidTholdHash checks if a threshold hash is valid (40 lowercase hex chars)
func IsValidTholdHash(hash string) bool {
	return len(hash) == TholdHashLength && IsValidHex(hash)
}

// IsValidCommitHash checks if a commit hash is valid (64 lowercase hex chars)
func IsValidCommitHash(hash string) bool {
	return len(hash) == CommitHashLength && IsValidHex(hash)
}

// IsValidContractID checks if a contract ID is valid (64 lowercase hex chars)
func IsValidContractID(id string) bool {
	return len(id) == ContractIDLength && IsValidHex(id)
}

// IsValidTholdKey checks if a threshold key is valid (64 lowercase hex chars)
func IsValidTholdKey(key string) bool {
	return len(key) == TholdKeyLength && IsValidHex(key)
}

// IsValidOracleSig checks if an oracle signature is valid (128 lowercase hex chars)
func IsValidOracleSig(sig string) bool {
	return len(sig) == OracleSigLength && IsValidHex(sig)
}

// IsValidSchnorrPubkey checks if a Schnorr public key is valid (64 lowercase hex chars)
func IsValidSchnorrPubkey(pubkey string) bool {
	return len(pubkey) == SchnorrPubkeyLength && IsValidHex(pubkey)
}

// ValidatePrice validates a price value
func ValidatePrice(price float64) error {
	// Check for NaN
	if math.IsNaN(price) {
		return fmt.Errorf("price is NaN")
	}
	// Check for infinity
	if math.IsInf(price, 0) {
		return fmt.Errorf("price is infinite")
	}
	// Check bounds
	if price <= 0 {
		return fmt.Errorf("price must be positive, got %.2f", price)
	}
	if price > MaxPriceValue {
		return fmt.Errorf("price exceeds maximum %.0f, got %.2f", MaxPriceValue, price)
	}
	return nil
}

// ValidateReasonablePrice validates a price is within reasonable BTC/USD bounds
func ValidateReasonablePrice(price float64) error {
	if err := ValidatePrice(price); err != nil {
		return err
	}
	if price < MinReasonablePrice {
		return fmt.Errorf("price below minimum reasonable value %.0f, got %.2f", MinReasonablePrice, price)
	}
	if price > MaxReasonablePrice {
		return fmt.Errorf("price above maximum reasonable value %.0f, got %.2f", MaxReasonablePrice, price)
	}
	return nil
}

// ValidateDomain validates a domain string
func ValidateDomain(domain string) error {
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	if len(domain) > MaxDomainLength {
		return fmt.Errorf("domain too long: max %d chars, got %d", MaxDomainLength, len(domain))
	}
	if !IsValidDomain(domain) {
		return fmt.Errorf("domain contains invalid characters (only alphanumeric, dots, hyphens, underscores allowed)")
	}
	return nil
}

// ValidateDomainWithSuffix validates a domain that will have a suffix appended
func ValidateDomainWithSuffix(domain string, suffixLen int) error {
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	maxLen := MaxDomainLength - suffixLen
	if len(domain) > maxLen {
		return fmt.Errorf("domain too long: max %d chars (with suffix), got %d", maxLen, len(domain))
	}
	if !IsValidDomain(domain) {
		return fmt.Errorf("domain contains invalid characters")
	}
	return nil
}

// ValidateTimestamp validates a Unix timestamp
func ValidateTimestamp(stamp int64) error {
	if stamp <= 0 {
		return fmt.Errorf("timestamp must be positive, got %d", stamp)
	}
	// Reasonable bounds: 2000-01-01 to 2100-01-01
	if stamp < 946684800 {
		return fmt.Errorf("timestamp too old (before year 2000), got %d", stamp)
	}
	if stamp > 4102444800 {
		return fmt.Errorf("timestamp too far in future (after year 2100), got %d", stamp)
	}
	return nil
}

// ValidateQuoteAge validates that a quote is not too old
func ValidateQuoteAge(quoteStamp, currentTime, maxAge int64) error {
	if quoteStamp <= 0 {
		return fmt.Errorf("invalid quote timestamp: %d", quoteStamp)
	}
	if currentTime <= 0 {
		return fmt.Errorf("invalid current timestamp: %d", currentTime)
	}
	if quoteStamp > currentTime {
		return fmt.Errorf("quote timestamp is in the future")
	}
	age := currentTime - quoteStamp
	if age > maxAge {
		return fmt.Errorf("quote too old: age %d seconds exceeds max %d", age, maxAge)
	}
	return nil
}
