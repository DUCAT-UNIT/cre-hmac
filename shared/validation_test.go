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
		{"fresh quote", currentTime - 1800, currentTime, maxAge, false, ""},
		{"at max age", currentTime - maxAge, currentTime, maxAge, false, ""},
		{"just created", currentTime, currentTime, maxAge, false, ""},

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
