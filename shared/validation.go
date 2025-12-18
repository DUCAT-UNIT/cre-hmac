package shared

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// Compiled regexes for validation (compiled once for performance)
//
// IMPORTANT: validHexRegex only accepts lowercase hex (0-9, a-f).
// Uppercase hex (A-F) is intentionally rejected for consistency with
// crypto package output (all hashes, signatures, and keys are lowercase).
// External integrations MUST normalize hex input to lowercase before validation.
//
// To normalize hex input: strings.ToLower(hexString)
var (
	validDomainRegex = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
	validHexRegex    = regexp.MustCompile(`^[0-9a-f]+$`)
)

// NormalizeHex converts a hex string to lowercase for consistent validation.
// Use this before calling any IsValid* hex validation functions on external input.
func NormalizeHex(hex string) string {
	return strings.ToLower(hex)
}

// IsValidDomain checks if domain contains only allowed characters
// Allows: alphanumeric, dots, hyphens, underscores
// IsValidDomain reports whether the provided domain is non-empty and contains only allowed characters: letters, digits, '.', '_', and '-'.
func IsValidDomain(domain string) bool {
	if domain == "" {
		return false
	}
	return validDomainRegex.MatchString(domain)
}

// IsValidHex reports whether s contains only lowercase hexadecimal characters (0-9 and a-f) and is non-empty.
func IsValidHex(s string) bool {
	if s == "" {
		return false
	}
	return validHexRegex.MatchString(s)
}

// IsValidTholdHash reports whether the provided hash is exactly TholdHashLength lowercase hexadecimal characters.
func IsValidTholdHash(hash string) bool {
	return len(hash) == TholdHashLength && IsValidHex(hash)
}

// IsValidCommitHash reports whether hash is a valid commit hash consisting of exactly 64 lowercase hexadecimal characters.
func IsValidCommitHash(hash string) bool {
	return len(hash) == CommitHashLength && IsValidHex(hash)
}

// IsValidContractID reports whether id is a valid contract identifier of exactly 64 lowercase hexadecimal characters.
// It returns `true` if id is exactly 64 characters long and contains only characters `0-9` and `a-f`, `false` otherwise.
func IsValidContractID(id string) bool {
	return len(id) == ContractIDLength && IsValidHex(id)
}

// IsValidTholdKey reports whether the provided key is a Thold key: a 64-character lowercase hexadecimal string.
func IsValidTholdKey(key string) bool {
	return len(key) == TholdKeyLength && IsValidHex(key)
}

// IsValidOracleSig reports whether sig is a valid oracle signature consisting of exactly 128 lowercase hexadecimal characters.
func IsValidOracleSig(sig string) bool {
	return len(sig) == OracleSigLength && IsValidHex(sig)
}

// IsValidSchnorrPubkey reports whether pubkey is a valid Schnorr public key of length SchnorrPubkeyLength containing only lowercase hexadecimal characters.
func IsValidSchnorrPubkey(pubkey string) bool {
	return len(pubkey) == SchnorrPubkeyLength && IsValidHex(pubkey)
}

// ValidatePrice checks that a price is a finite, positive value within allowed maximum bounds.
// It returns an error if the price is NaN, infinite, less than or equal to zero, or greater than MaxPriceValue.
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

// ValidateReasonablePrice checks that price is finite, greater than zero, not above the configured absolute maximum, and within the configured reasonable BTC/USD range.
// It returns an error describing the specific constraint violated (NaN, infinite, non-positive, above absolute max, below minimum reasonable, or above maximum reasonable).
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

// ValidateDomain checks that domain is non-empty, does not exceed MaxDomainLength,
// and contains only allowed characters: letters, digits, '.', '-', and '_'.
// If validation fails, it returns an error describing the first failure.
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

// ValidateDomainWithSuffix checks that domain is non-empty, contains only allowed characters,
// and fits within MaxDomainLength when a suffix of length suffixLen will be appended.
// It returns an error describing the first validation failure, or nil if the domain is valid.
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

// ValidateTimestamp ensures stamp is a positive Unix timestamp within the range
// 2000-01-01 (Unix 946684800) to 2100-01-01 (Unix 4102444800); it returns an error
// when the value is non-positive, earlier than 2000-01-01, or later than 2100-01-01.
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

// ValidateQuoteAge ensures the quote timestamp is valid, not in the future, and its age does not exceed maxAge.
// It returns an error if `quoteStamp` or `currentTime` are non-positive, if `quoteStamp` is after `currentTime`, or if the computed age (`currentTime - quoteStamp`) exceeds `maxAge`.
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