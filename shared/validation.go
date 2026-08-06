package shared

import (
	"fmt"
	"math"
	"net"
	"net/url"
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

// IsThresholdBreached evaluates a threshold in the direction established when
// the quote was created. A threshold below the base price is breached on a
// downward crossing; a threshold above the base price is breached on an upward
// crossing. Inferring the direction from signed commitment data keeps the
// decision deterministic without adding an unsigned request field.
func IsThresholdBreached(basePrice, thresholdPrice, currentPrice float64) (bool, error) {
	if err := ValidatePrice(basePrice); err != nil {
		return false, fmt.Errorf("invalid base price: %w", err)
	}
	if err := ValidatePrice(thresholdPrice); err != nil {
		return false, fmt.Errorf("invalid threshold price: %w", err)
	}
	if err := ValidatePrice(currentPrice); err != nil {
		return false, fmt.Errorf("invalid current price: %w", err)
	}
	if thresholdPrice == basePrice {
		return false, fmt.Errorf("threshold price must differ from base price")
	}
	if thresholdPrice < basePrice {
		return currentPrice < thresholdPrice, nil
	}
	return currentPrice > thresholdPrice, nil
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

// ValidateBatchPublishResult rejects contradictory or incomplete relay batch
// acknowledgements. A current snapshot must never be promoted unless the relay
// explicitly confirms that every event in the preceding batch was stored.
func ValidateBatchPublishResult(success bool, published, failed, expected int) error {
	if expected < 0 {
		return fmt.Errorf("expected batch size cannot be negative: %d", expected)
	}
	if published < 0 || failed < 0 || published+failed != expected {
		return fmt.Errorf("inconsistent batch result: published=%d failed=%d expected=%d", published, failed, expected)
	}
	complete := published == expected && failed == 0
	if success != complete {
		return fmt.Errorf("contradictory batch result: success=%t published=%d failed=%d expected=%d", success, published, failed, expected)
	}
	return nil
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

// ValidateCallbackURL validates an outbound callback/webhook URL as a defense
// in depth against SSRF and data exfiltration (M4).
//
// The oracle posts quote/evaluation results to caller-supplied callback URLs and
// to the configured regulator URL. Without validation, a request could point the
// oracle at internal-only endpoints (cloud metadata, loopback admin APIs, private
// RFC1918 services) and either pivot inside the network or exfiltrate signed
// payloads. This function enforces:
//   - scheme must be exactly "https" (no http, no file://, no gopher://, etc.)
//   - host must be present
//   - if the host is a literal IP, it must NOT be loopback, private (RFC1918 /
//     ULA), link-local, or unspecified
//   - host must not be "localhost" or the GCP metadata host
//     "metadata.google.internal"
//
// Note: this is best-effort static validation. It cannot catch a public hostname
// that later resolves to a private IP (DNS rebinding) — that requires controls at
// the HTTP egress layer. It rejects the obvious literal cases. An empty string is
// rejected (callers must skip the call entirely when the field is unset rather
// than passing "" here).
func ValidateCallbackURL(raw string) error {
	if raw == "" {
		return fmt.Errorf("callback url is empty")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("callback url is not a valid URL: %w", err)
	}

	if u.Scheme != "https" {
		return fmt.Errorf("callback url must use https scheme, got %q", u.Scheme)
	}
	if u.User != nil {
		return fmt.Errorf("callback url must not contain userinfo")
	}

	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("callback url has empty host")
	}
	// net.ParseIP intentionally rejects IPv6 zone identifiers. Treating a
	// zoned literal as a DNS name would let loopback/link-local destinations
	// such as [::1%lo0] bypass the literal-IP checks below.
	if strings.Contains(host, "%") {
		return fmt.Errorf("callback url host must not contain an IPv6 zone identifier")
	}

	// Normalize: a single trailing dot (FQDN form, e.g. "localhost." or
	// "127.0.0.1.") resolves to the same target but would bypass the literal
	// hostname/IP comparisons below, so strip it before checking. (SSRF bypass.)
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return fmt.Errorf("callback url has empty host")
	}

	// Reject known dangerous hostnames outright.
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" {
		return fmt.Errorf("callback url host %q is not allowed", host)
	}
	if lowerHost == "metadata.google.internal" {
		return fmt.Errorf("callback url host %q is not allowed", host)
	}

	// If the host is a literal IP address, reject loopback / private / link-local
	// / unspecified ranges. (Hostnames are intentionally left to egress controls.)
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() {
			return fmt.Errorf("callback url points at a loopback IP %q", host)
		}
		if ip.IsPrivate() {
			return fmt.Errorf("callback url points at a private IP %q", host)
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("callback url points at a link-local IP %q", host)
		}
		if ip.IsUnspecified() {
			return fmt.Errorf("callback url points at an unspecified IP %q", host)
		}
	} else if isNumericHost(host) {
		// The host is all digits/dots/hex (no letters) but net.ParseIP rejected
		// it — i.e. an alternate IP encoding like octal "0177.0.0.1", 32-bit
		// decimal "2130706433", or hex "0x7f.1". The OS resolver/dialer would
		// still connect to the underlying (often loopback/private) address, so
		// reject these outright. A legitimate callback host is a DNS name (has
		// letters) or a canonical dotted-quad (handled by net.ParseIP above).
		return fmt.Errorf("callback url host %q is a non-canonical numeric address", host)
	}

	return nil
}

// isNumericHost reports whether host is an alternate numeric IP encoding that
// net.ParseIP does not recognize but the OS resolver/dialer still maps to an IP
// (e.g. octal "0177.0.0.1", 32-bit decimal "2130706433", hex "0x7f000001").
// A real DNS hostname has a non-hex letter somewhere or a TLD; these forms are
// composed only of digits and dots, or carry a leading "0x" hex marker.
func isNumericHost(host string) bool {
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	// Hex IP form: 0x... (optionally dotted, e.g. 0x7f.0x0.0x0.0x1).
	if strings.HasPrefix(lower, "0x") {
		return true
	}
	// Digits-and-dots only (decimal or octal dotted/flat forms). A genuine DNS
	// name always has at least one alphabetic label, so this never matches one.
	hasDigit := false
	for _, r := range host {
		switch {
		case r >= '0' && r <= '9':
			hasDigit = true
		case r == '.':
			// allowed separator
		default:
			return false // any letter/other char => DNS name, not numeric
		}
	}
	return hasDigit
}
