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
	if price > float64(MaxPriceValue) {
		return fmt.Errorf("price exceeds maximum %d, got %.2f", MaxPriceValue, price)
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

// TruncatePriceToUint32 converts a float64 price to uint32 using floor truncation.
// This matches the TypeScript core-ts implementation which uses Buff.num(value, 4)
// for 4-byte big-endian encoding, discarding fractional values.
//
// SECURITY: Prices MUST be truncated consistently across oracle and client.
// Using math.Floor ensures deterministic behavior - a price of 100234.99 becomes
// 100234, never 100235. This prevents hash mismatches and potential arbitrage.
//
// Returns an error if the price:
//   - Is negative (would underflow)
//   - Is NaN or infinite
//   - Exceeds MaxPriceValue (uint32 max = 4,294,967,295)
func TruncatePriceToUint32(price float64) (uint32, error) {
	// Reject NaN
	if math.IsNaN(price) {
		return 0, fmt.Errorf("cannot truncate NaN price")
	}
	// Reject infinity
	if math.IsInf(price, 0) {
		return 0, fmt.Errorf("cannot truncate infinite price")
	}
	// Reject negative prices
	if price < 0 {
		return 0, fmt.Errorf("cannot truncate negative price: %.2f", price)
	}
	// Reject prices exceeding uint32 max
	if price > float64(MaxPriceValue) {
		return 0, fmt.Errorf("price %.2f exceeds uint32 max (%d)", price, MaxPriceValue)
	}

	// Use math.Floor for explicit truncation toward zero
	// This ensures deterministic behavior matching TypeScript
	truncated := math.Floor(price)
	return uint32(truncated), nil
}

// MustTruncatePriceToUint32 is like TruncatePriceToUint32 but panics on error.
// Only use this when the price has already been validated.
func MustTruncatePriceToUint32(price float64) uint32 {
	result, err := TruncatePriceToUint32(price)
	if err != nil {
		panic(fmt.Sprintf("MustTruncatePriceToUint32: %v", err))
	}
	return result
}

// ValidateCronExpression validates a 6-field cron expression.
// Format: second minute hour day month weekday
// Examples:
//   - "0 */5 * * * *" - every 5 minutes
//   - "0 */90 * * * *" - every 90 seconds
//   - "0 0 * * * *" - every hour
//
// Supports: numbers, *, /, - (ranges), and , (lists)
func ValidateCronExpression(expr string) error {
	if expr == "" {
		return fmt.Errorf("cron expression cannot be empty")
	}

	fields := strings.Fields(expr)
	if len(fields) != 6 {
		return fmt.Errorf("cron expression must have 6 fields (second minute hour day month weekday), got %d", len(fields))
	}

	// Field constraints: [min, max]
	constraints := []struct {
		name string
		min  int
		max  int
	}{
		{"second", 0, 59},
		{"minute", 0, 59},
		{"hour", 0, 23},
		{"day", 1, 31},
		{"month", 1, 12},
		{"weekday", 0, 6},
	}

	for i, field := range fields {
		if err := validateCronField(field, constraints[i].name, constraints[i].min, constraints[i].max); err != nil {
			return err
		}
	}

	return nil
}

// validateCronField validates a single cron field
func validateCronField(field, name string, min, max int) error {
	// Handle wildcard
	if field == "*" {
		return nil
	}

	// Handle lists (e.g., "1,2,3")
	if strings.Contains(field, ",") {
		parts := strings.Split(field, ",")
		for _, part := range parts {
			if err := validateCronField(part, name, min, max); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle step values (e.g., "*/5" or "0-30/5")
	if strings.Contains(field, "/") {
		parts := strings.Split(field, "/")
		if len(parts) != 2 {
			return fmt.Errorf("invalid step in %s field: %s", name, field)
		}
		// Validate the step value
		var step int
		if _, err := fmt.Sscanf(parts[1], "%d", &step); err != nil || step <= 0 {
			return fmt.Errorf("invalid step value in %s field: %s", name, field)
		}
		// Validate the base (could be * or a range)
		if parts[0] != "*" {
			if err := validateCronField(parts[0], name, min, max); err != nil {
				return err
			}
		}
		return nil
	}

	// Handle ranges (e.g., "1-5")
	if strings.Contains(field, "-") {
		parts := strings.Split(field, "-")
		if len(parts) != 2 {
			return fmt.Errorf("invalid range in %s field: %s", name, field)
		}
		var start, end int
		if _, err := fmt.Sscanf(parts[0], "%d", &start); err != nil {
			return fmt.Errorf("invalid range start in %s field: %s", name, field)
		}
		if _, err := fmt.Sscanf(parts[1], "%d", &end); err != nil {
			return fmt.Errorf("invalid range end in %s field: %s", name, field)
		}
		if start < min || start > max {
			return fmt.Errorf("%s field range start %d out of bounds [%d-%d]", name, start, min, max)
		}
		if end < min || end > max {
			return fmt.Errorf("%s field range end %d out of bounds [%d-%d]", name, end, min, max)
		}
		if start > end {
			return fmt.Errorf("%s field range start %d > end %d", name, start, end)
		}
		return nil
	}

	// Handle single number
	var val int
	if _, err := fmt.Sscanf(field, "%d", &val); err != nil {
		return fmt.Errorf("invalid value in %s field: %s", name, field)
	}
	if val < min || val > max {
		return fmt.Errorf("%s field value %d out of bounds [%d-%d]", name, val, min, max)
	}

	return nil
}