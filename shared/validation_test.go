package shared

import (
	"math"
	"strings"
	"testing"
)

// =============================================================================
// Domain Validation Tests
// =============================================================================

func TestIsValidDomain(t *testing.T) {
	tests := []struct {
		name   string
		domain string
		want   bool
	}{
		// Valid domains
		{"simple alphanumeric", "test123", true},
		{"with dots", "test.domain.com", true},
		{"with hyphens", "test-domain-name", true},
		{"with underscores", "test_domain_name", true},
		{"mixed valid chars", "test-123_domain.name", true},
		{"uppercase", "TestDomain", true},
		{"single char", "a", true},
		{"numbers only", "123456", true},

		// Invalid domains
		{"empty string", "", false},
		{"with spaces", "test domain", false},
		{"with special chars", "test@domain", false},
		{"with slash", "test/domain", false},
		{"with backslash", "test\\domain", false},
		{"with colon", "test:domain", false},
		{"with semicolon", "test;domain", false},
		{"with quotes", "test\"domain", false},
		{"with angle brackets", "test<domain>", false},
		{"with pipe", "test|domain", false},
		{"with asterisk", "test*domain", false},
		{"with question mark", "test?domain", false},
		{"with newline", "test\ndomain", false},
		{"with tab", "test\tdomain", false},
		{"with null byte", "test\x00domain", false},
		{"unicode chars", "tëst", false},
		{"emoji", "test🎉", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidDomain(tt.domain)
			if got != tt.want {
				t.Errorf("IsValidDomain(%q) = %v, want %v", tt.domain, got, tt.want)
			}
		})
	}
}

func TestValidateDomain(t *testing.T) {
	tests := []struct {
		name    string
		domain  string
		wantErr bool
		errMsg  string
	}{
		{"valid domain", "test-domain", false, ""},
		{"empty domain", "", true, "domain required"},
		{"too long domain", strings.Repeat("a", MaxDomainLength+1), true, "domain too long"},
		{"max length domain", strings.Repeat("a", MaxDomainLength), false, ""},
		{"invalid chars", "test@domain", true, "invalid characters"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomain(tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomain(%q) error = %v, wantErr %v", tt.domain, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateDomain(%q) error = %v, want error containing %q", tt.domain, err, tt.errMsg)
			}
		})
	}
}

func TestValidateDomainWithSuffix(t *testing.T) {
	tests := []struct {
		name      string
		domain    string
		suffixLen int
		wantErr   bool
	}{
		{"valid with suffix room", "test", 20, false},
		{"too long with suffix", strings.Repeat("a", MaxDomainLength-10), 20, true},
		{"exactly at limit", strings.Repeat("a", MaxDomainLength-20), 20, false},
		{"empty domain", "", 20, true},
		{"invalid chars", "test@domain", 20, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateDomainWithSuffix(tt.domain, tt.suffixLen)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateDomainWithSuffix(%q, %d) error = %v, wantErr %v", tt.domain, tt.suffixLen, err, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Hex Validation Tests
// =============================================================================

func TestIsValidHex(t *testing.T) {
	tests := []struct {
		name string
		s    string
		want bool
	}{
		// Valid hex
		{"lowercase hex", "0123456789abcdef", true},
		{"all zeros", "0000000000000000", true},
		{"all f's", "ffffffffffffffff", true},
		{"single char", "a", true},
		{"mixed digits and letters", "1a2b3c4d5e6f", true},

		// Invalid hex
		{"empty string", "", false},
		{"uppercase", "ABCDEF", false},
		{"mixed case", "abCDef", false},
		{"with space", "ab cd", false},
		{"with g", "abcdefg", false},
		{"with special char", "abcdef!", false},
		{"with 0x prefix", "0xabcdef", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidHex(tt.s)
			if got != tt.want {
				t.Errorf("IsValidHex(%q) = %v, want %v", tt.s, got, tt.want)
			}
		})
	}
}

func TestIsValidTholdHash(t *testing.T) {
	validHash := strings.Repeat("a", 40)
	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"valid 40 char hash", validHash, true},
		{"too short", strings.Repeat("a", 39), false},
		{"too long", strings.Repeat("a", 41), false},
		{"empty", "", false},
		{"invalid chars", strings.Repeat("g", 40), false},
		{"uppercase", strings.Repeat("A", 40), false},
		{"mixed valid/invalid length", "abc", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTholdHash(tt.hash)
			if got != tt.want {
				t.Errorf("IsValidTholdHash(%q) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

func TestIsValidCommitHash(t *testing.T) {
	validHash := strings.Repeat("a", 64)
	tests := []struct {
		name string
		hash string
		want bool
	}{
		{"valid 64 char hash", validHash, true},
		{"too short", strings.Repeat("a", 63), false},
		{"too long", strings.Repeat("a", 65), false},
		{"empty", "", false},
		{"invalid chars", strings.Repeat("g", 64), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidCommitHash(tt.hash)
			if got != tt.want {
				t.Errorf("IsValidCommitHash(%q) = %v, want %v", tt.hash, got, tt.want)
			}
		})
	}
}

func TestIsValidContractID(t *testing.T) {
	validID := strings.Repeat("b", 64)
	tests := []struct {
		name string
		id   string
		want bool
	}{
		{"valid 64 char ID", validID, true},
		{"too short", strings.Repeat("b", 63), false},
		{"too long", strings.Repeat("b", 65), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidContractID(tt.id)
			if got != tt.want {
				t.Errorf("IsValidContractID(%q) = %v, want %v", tt.id, got, tt.want)
			}
		})
	}
}

func TestIsValidTholdKey(t *testing.T) {
	validKey := strings.Repeat("c", 64)
	tests := []struct {
		name string
		key  string
		want bool
	}{
		{"valid 64 char key", validKey, true},
		{"too short", strings.Repeat("c", 63), false},
		{"too long", strings.Repeat("c", 65), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidTholdKey(tt.key)
			if got != tt.want {
				t.Errorf("IsValidTholdKey(%q) = %v, want %v", tt.key, got, tt.want)
			}
		})
	}
}

func TestIsValidOracleSig(t *testing.T) {
	validSig := strings.Repeat("d", 128)
	tests := []struct {
		name string
		sig  string
		want bool
	}{
		{"valid 128 char sig", validSig, true},
		{"too short", strings.Repeat("d", 127), false},
		{"too long", strings.Repeat("d", 129), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidOracleSig(tt.sig)
			if got != tt.want {
				t.Errorf("IsValidOracleSig(%q) = %v, want %v", tt.sig, got, tt.want)
			}
		})
	}
}

func TestIsValidSchnorrPubkey(t *testing.T) {
	validPubkey := strings.Repeat("e", 64)
	tests := []struct {
		name   string
		pubkey string
		want   bool
	}{
		{"valid 64 char pubkey", validPubkey, true},
		{"too short", strings.Repeat("e", 63), false},
		{"too long", strings.Repeat("e", 65), false},
		{"empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := IsValidSchnorrPubkey(tt.pubkey)
			if got != tt.want {
				t.Errorf("IsValidSchnorrPubkey(%q) = %v, want %v", tt.pubkey, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Price Validation Tests
// =============================================================================

func TestValidatePrice(t *testing.T) {
	tests := []struct {
		name    string
		price   float64
		wantErr bool
		errMsg  string
	}{
		// Valid prices
		{"positive price", 100000.0, false, ""},
		{"small positive", 0.01, false, ""},
		{"large price", 1e9, false, ""},                        // $1B is valid
		{"max price", float64(MaxPriceValue), false, ""},       // uint32 max

		// Invalid prices
		{"zero", 0, true, "must be positive"},
		{"negative", -100.0, true, "must be positive"},
		{"exceeds max", float64(MaxPriceValue) + 1, true, "exceeds maximum"},
		{"NaN", math.NaN(), true, "NaN"},
		{"positive infinity", math.Inf(1), true, "infinite"},
		{"negative infinity", math.Inf(-1), true, "infinite"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePrice(tt.price)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidatePrice(%v) error = %v, wantErr %v", tt.price, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidatePrice(%v) error = %v, want error containing %q", tt.price, err, tt.errMsg)
			}
		})
	}
}

func TestValidateReasonablePrice(t *testing.T) {
	tests := []struct {
		name    string
		price   float64
		wantErr bool
		errMsg  string
	}{
		// Valid reasonable prices
		{"typical BTC price", 50000.0, false, ""},
		{"min reasonable", MinReasonablePrice, false, ""},
		{"max reasonable", MaxReasonablePrice, false, ""},

		// Invalid prices
		{"below min", MinReasonablePrice - 1, true, "below minimum"},
		{"above max", MaxReasonablePrice + 1, true, "above maximum"},
		{"zero", 0, true, "must be positive"},
		{"NaN", math.NaN(), true, "NaN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateReasonablePrice(tt.price)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateReasonablePrice(%v) error = %v, wantErr %v", tt.price, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateReasonablePrice(%v) error = %v, want error containing %q", tt.price, err, tt.errMsg)
			}
		})
	}
}

// =============================================================================
// Timestamp Validation Tests
// =============================================================================

func TestValidateTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		stamp   int64
		wantErr bool
		errMsg  string
	}{
		// Valid timestamps
		{"current era", 1700000000, false, ""},
		{"year 2000", 946684800, false, ""},
		{"year 2099", 4070908800, false, ""},

		// Invalid timestamps
		{"zero", 0, true, "must be positive"},
		{"negative", -1, true, "must be positive"},
		{"before 2000", 946684799, true, "too old"},
		{"after 2100", 4102444801, true, "too far in future"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateTimestamp(tt.stamp)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateTimestamp(%d) error = %v, wantErr %v", tt.stamp, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateTimestamp(%d) error = %v, want error containing %q", tt.stamp, err, tt.errMsg)
			}
		})
	}
}

func TestValidateQuoteAge(t *testing.T) {
	currentTime := int64(1700000000)
	maxAge := int64(MaxQuoteAge)

	tests := []struct {
		name        string
		quoteStamp  int64
		currentTime int64
		maxAge      int64
		wantErr     bool
		errMsg      string
	}{
		// Valid ages
		{"fresh quote", currentTime - 30, currentTime, maxAge, false, ""},      // 30 seconds old
		{"at max age", currentTime - maxAge, currentTime, maxAge, false, ""},   // exactly at max (60 sec)
		{"just created", currentTime, currentTime, maxAge, false, ""},          // brand new

		// Invalid ages
		{"too old", currentTime - maxAge - 1, currentTime, maxAge, true, "too old"},
		{"future quote", currentTime + 100, currentTime, maxAge, true, "future"},
		{"invalid quote stamp", 0, currentTime, maxAge, true, "invalid quote timestamp"},
		{"invalid current stamp", currentTime, 0, maxAge, true, "invalid current timestamp"},
		{"negative quote stamp", -1, currentTime, maxAge, true, "invalid quote timestamp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQuoteAge(tt.quoteStamp, tt.currentTime, tt.maxAge)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQuoteAge(%d, %d, %d) error = %v, wantErr %v",
					tt.quoteStamp, tt.currentTime, tt.maxAge, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateQuoteAge() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// =============================================================================
// Price Truncation Tests
// =============================================================================

func TestTruncatePriceToUint32(t *testing.T) {
	tests := []struct {
		name    string
		price   float64
		want    uint32
		wantErr bool
		errMsg  string
	}{
		// Valid prices - floor truncation behavior
		{"whole number", 100000.0, 100000, false, ""},
		{"with fraction (floor)", 100000.99, 100000, false, ""},
		{"with small fraction", 100000.01, 100000, false, ""},
		{"exactly 0.5", 100000.5, 100000, false, ""},
		{"zero", 0.0, 0, false, ""},
		{"small positive", 1.0, 1, false, ""},
		{"max uint32", float64(MaxPriceValue), MaxPriceValue, false, ""},

		// Invalid prices
		{"negative", -100.0, 0, true, "negative"},
		{"NaN", math.NaN(), 0, true, "NaN"},
		{"positive infinity", math.Inf(1), 0, true, "infinite"},
		{"negative infinity", math.Inf(-1), 0, true, "infinite"},
		{"exceeds uint32 max", float64(MaxPriceValue) + 1, 0, true, "exceeds uint32"},
		{"large overflow", 1e15, 0, true, "exceeds uint32"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := TruncatePriceToUint32(tt.price)
			if (err != nil) != tt.wantErr {
				t.Errorf("TruncatePriceToUint32(%v) error = %v, wantErr %v", tt.price, err, tt.wantErr)
				return
			}
			if !tt.wantErr && got != tt.want {
				t.Errorf("TruncatePriceToUint32(%v) = %d, want %d", tt.price, got, tt.want)
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("TruncatePriceToUint32(%v) error = %v, want error containing %q", tt.price, err, tt.errMsg)
			}
		})
	}
}

func TestMustTruncatePriceToUint32(t *testing.T) {
	// Valid case - should not panic
	result := MustTruncatePriceToUint32(100000.99)
	if result != 100000 {
		t.Errorf("MustTruncatePriceToUint32(100000.99) = %d, want 100000", result)
	}

	// Invalid case - should panic
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustTruncatePriceToUint32(-1) should panic")
		}
	}()
	MustTruncatePriceToUint32(-1)
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkIsValidDomain(b *testing.B) {
	domain := "test-domain.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidDomain(domain)
	}
}

func BenchmarkIsValidHex(b *testing.B) {
	hex := strings.Repeat("a", 64)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		IsValidHex(hex)
	}
}

func BenchmarkValidatePrice(b *testing.B) {
	price := 50000.0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidatePrice(price)
	}
}

func BenchmarkValidateDomain(b *testing.B) {
	domain := "test-domain.example.com"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ValidateDomain(domain)
	}
}

// =============================================================================
// URL Validation Tests
// =============================================================================

func TestValidateCallbackURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
		errMsg  string
	}{
		// Valid URLs
		{"empty (optional)", "", false, ""},
		{"https URL", "https://example.com/webhook", false, ""},
		{"https with port", "https://example.com:8443/webhook", false, ""},
		{"localhost http", "http://localhost:8080/callback", false, ""},
		{"127.0.0.1 http", "http://127.0.0.1:3000/webhook", false, ""},
		{"localhost https", "https://localhost/callback", false, ""},

		// Invalid URLs
		{"http non-localhost", "http://example.com/webhook", true, "must use https://"},
		{"no scheme", "example.com/webhook", true, "must have a scheme"},
		{"no host", "https:///path", true, "must have a host"},
		{"ftp scheme", "ftp://example.com/file", true, "must use http:// or https://"},
		{"ws scheme", "ws://example.com/ws", true, "must use http:// or https://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCallbackURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCallbackURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateCallbackURL(%q) error = %v, want error containing %q", tt.url, err, tt.errMsg)
			}
		})
	}
}

func TestValidateServiceURL(t *testing.T) {
	tests := []struct {
		name        string
		url         string
		serviceName string
		wantErr     bool
		errMsg      string
	}{
		// Valid URLs
		{"https URL", "https://api.example.com", "data_stream", false, ""},
		{"wss URL", "wss://relay.example.com", "relay", false, ""},
		{"localhost http", "http://localhost:8080", "relay", false, ""},
		{"localhost ws", "ws://localhost:7000", "relay", false, ""},
		{"127.0.0.1 http", "http://127.0.0.1:3000", "data_stream", false, ""},

		// Invalid URLs
		{"empty URL", "", "relay", true, "URL is required"},
		{"http non-localhost", "http://api.example.com", "data_stream", true, "must use TLS"},
		{"ws non-localhost", "ws://relay.example.com", "relay", true, "must use TLS"},
		{"no scheme", "example.com", "relay", true, "must have a scheme"},
		{"no host", "https:///path", "data_stream", true, "must have a host"},
		{"ftp scheme", "ftp://example.com", "relay", true, "must use http://"},
		{"invalid scheme", "gopher://example.com", "data_stream", true, "must use http://"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateServiceURL(tt.url, tt.serviceName)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateServiceURL(%q, %q) error = %v, wantErr %v", tt.url, tt.serviceName, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateServiceURL(%q, %q) error = %v, want error containing %q", tt.url, tt.serviceName, err, tt.errMsg)
			}
		})
	}
}

// =============================================================================
// Cron Expression Validation Tests
// =============================================================================

func TestValidateCronExpression(t *testing.T) {
	tests := []struct {
		name    string
		expr    string
		wantErr bool
		errMsg  string
	}{
		// Valid expressions
		{"every minute", "0 * * * * *", false, ""},
		{"every 5 minutes", "0 */5 * * * *", false, ""},
		{"every hour", "0 0 * * * *", false, ""},
		{"specific time", "0 30 9 * * *", false, ""},
		{"weekday only", "0 0 8 * * 1-5", false, ""},
		{"list values", "0 0,15,30,45 * * * *", false, ""},
		{"range values", "0 0 9-17 * * *", false, ""},
		{"step with range", "0 0-30/5 * * * *", false, ""},
		{"complex", "30 */15 9-17 * * 1-5", false, ""},

		// Invalid expressions
		{"empty", "", true, "cannot be empty"},
		{"too few fields", "0 * * * *", true, "must have 6 fields"},
		{"too many fields", "0 * * * * * *", true, "must have 6 fields"},
		{"invalid second", "60 * * * * *", true, "out of bounds"},
		{"invalid minute", "0 60 * * * *", true, "out of bounds"},
		{"invalid hour", "0 0 24 * * *", true, "out of bounds"},
		{"invalid day", "0 0 0 32 * *", true, "out of bounds"},
		{"invalid month", "0 0 0 1 13 *", true, "out of bounds"},
		{"invalid weekday", "0 0 0 * * 7", true, "out of bounds"},
		{"invalid step", "0 */0 * * * *", true, "invalid step"},
		{"invalid range format", "0 1-2-3 * * * *", true, "invalid range"},
		{"invalid number", "0 abc * * * *", true, "invalid"},
		{"negative number", "0 -1 * * * *", true, "invalid range"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCronExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCronExpression(%q) error = %v, wantErr %v", tt.expr, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateCronExpression(%q) error = %v, want error containing %q", tt.expr, err, tt.errMsg)
			}
		})
	}
}

func TestValidateCronField(t *testing.T) {
	// Test the internal validateCronField function through ValidateCronExpression
	// This tests edge cases not covered by the main tests

	tests := []struct {
		name    string
		expr    string
		wantErr bool
		errMsg  string
	}{
		// Step edge cases
		{"step with invalid base", "0 abc/5 * * * *", true, "invalid"},
		{"step with zero", "0 */0 * * * *", true, "invalid step"},
		{"step with negative", "0 */-1 * * * *", true, "invalid step"},

		// Range edge cases
		{"range reversed", "0 30-10 * * * *", true, "range start"},
		{"range start invalid", "0 abc-10 * * * *", true, "invalid range start"},
		{"range end invalid", "0 10-abc * * * *", true, "invalid range end"},

		// List edge cases
		{"list with invalid", "0 1,abc,3 * * * *", true, "invalid"},
		{"list with out of bounds", "0 1,2,100 * * * *", true, "out of bounds"},

		// Boundary values
		{"day min boundary", "0 0 0 0 * *", true, "out of bounds"},
		{"month min boundary", "0 0 0 1 0 *", true, "out of bounds"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCronExpression(tt.expr)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCronExpression(%q) error = %v, wantErr %v", tt.expr, err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("ValidateCronExpression(%q) error = %v, want error containing %q", tt.expr, err, tt.errMsg)
			}
		})
	}
}
