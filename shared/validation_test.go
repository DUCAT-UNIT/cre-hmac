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
		{"large price", 1e9, false, ""},                  // $1B is valid
		{"max price", float64(MaxPriceValue), false, ""}, // uint32 max

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
		{"fresh quote", currentTime - 30, currentTime, maxAge, false, ""},    // 30 seconds old
		{"at max age", currentTime - maxAge, currentTime, maxAge, false, ""}, // exactly at max (60 sec)
		{"just created", currentTime, currentTime, maxAge, false, ""},        // brand new

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

func TestValidateBatchPublishResult(t *testing.T) {
	tests := []struct {
		name                        string
		success, wantErr            bool
		published, failed, expected int
	}{
		{"complete success", true, false, 3, 0, 3},
		{"reported partial failure", false, false, 2, 1, 3},
		{"success with partial counts", true, true, 2, 1, 3},
		{"failure with complete counts", false, true, 3, 0, 3},
		{"counts do not add up", false, true, 1, 1, 3},
		{"negative count", false, true, -1, 4, 3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBatchPublishResult(tt.success, tt.published, tt.failed, tt.expected)
			if (err != nil) != tt.wantErr {
				t.Fatalf("ValidateBatchPublishResult() error = %v, wantErr %t", err, tt.wantErr)
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
// Callback URL Validation Tests (M4)
// =============================================================================

func TestValidateCallbackURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		wantErr bool
	}{
		// Valid
		{"valid https url", "https://regulator.ducatprotocol.com/webhook/ducat", false},
		{"valid https with port", "https://example.com:8443/cb", false},
		{"valid https public IP", "https://93.184.216.34/cb", false},

		// Scheme rejected
		{"http rejected", "http://example.com/cb", true},
		{"ftp rejected", "ftp://example.com/cb", true},
		{"file rejected", "file:///etc/passwd", true},
		{"no scheme rejected", "example.com/cb", true},

		// Empty / malformed
		{"empty rejected", "", true},
		{"scheme only no host", "https://", true},
		{"userinfo rejected", "https://user:secret@example.com/cb", true},

		// Dangerous hosts
		{"localhost rejected", "https://localhost/cb", true},
		{"localhost uppercase rejected", "https://LOCALHOST/cb", true},
		{"localhost with port rejected", "https://localhost:9000/cb", true},
		{"metadata host rejected", "https://metadata.google.internal/computeMetadata/v1/", true},

		// Literal private/loopback/link-local/unspecified IPs
		{"loopback 127.0.0.1 rejected", "https://127.0.0.1/cb", true},
		{"loopback ipv6 rejected", "https://[::1]/cb", true},
		{"zoned loopback ipv6 rejected", "https://[::1%25lo0]/cb", true},
		{"zoned link-local ipv6 rejected", "https://[fe80::1%25en0]/cb", true},
		{"private 10.x rejected", "https://10.0.0.5/cb", true},
		{"private 192.168.x rejected", "https://192.168.1.1/cb", true},
		{"private 172.16.x rejected", "https://172.16.0.1/cb", true},
		{"link-local 169.254.x rejected", "https://169.254.169.254/cb", true},
		{"unspecified 0.0.0.0 rejected", "https://0.0.0.0/cb", true},
		{"unique-local ipv6 rejected", "https://[fd00::1]/cb", true},

		// SSRF bypasses (caught by adversarial review): trailing-dot FQDN forms
		{"trailing-dot localhost rejected", "https://localhost./cb", true},
		{"trailing-dot metadata rejected", "https://metadata.google.internal./computeMetadata/v1/", true},
		{"trailing-dot loopback rejected", "https://127.0.0.1./cb", true},
		// SSRF bypasses: alternate numeric IP encodings of 127.0.0.1
		{"octal loopback rejected", "https://0177.0.0.1/cb", true},
		{"decimal loopback rejected", "https://2130706433/cb", true},
		{"hex loopback rejected", "https://0x7f000001/cb", true},
		{"dotted-hex loopback rejected", "https://0x7f.0x0.0x0.0x1/cb", true},
		// Trailing-dot on a legit public host is still allowed
		{"trailing-dot public host allowed", "https://example.com./cb", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateCallbackURL(tt.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateCallbackURL(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
			}
		})
	}
}

func TestIsThresholdBreached(t *testing.T) {
	tests := []struct {
		name                     string
		base, threshold, current float64
		want                     bool
		wantErr                  bool
	}{
		{"downward active", 100, 90, 95, false, false},
		{"downward breached", 100, 90, 89, true, false},
		{"downward equality remains active", 100, 90, 90, false, false},
		{"upward active", 100, 110, 109, false, false},
		{"upward equality remains active", 100, 110, 110, false, false},
		{"upward breached", 100, 110, 111, true, false},
		{"equal base and threshold rejected", 100, 100, 100, false, true},
		{"invalid current rejected", 100, 90, math.NaN(), false, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := IsThresholdBreached(tt.base, tt.threshold, tt.current)
			if (err != nil) != tt.wantErr {
				t.Fatalf("IsThresholdBreached() error = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Fatalf("IsThresholdBreached() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestValidateCallbackURL_CallerSkipsEmpty documents the contract that callers
// skip ValidateCallbackURL when the field is unset/empty. ValidateCallbackURL
// itself always rejects an empty string (empty host), so callers MUST guard with
// a non-empty check before invoking it (mirroring the Validate() methods).
func TestValidateCallbackURL_CallerSkipsEmpty(t *testing.T) {
	if err := ValidateCallbackURL(""); err == nil {
		t.Fatal("expected ValidateCallbackURL(\"\") to reject empty, got nil")
	}

	// Caller-side pattern: skip when empty, so an empty optional field passes.
	var callbackURL *string
	if callbackURL != nil && *callbackURL != "" {
		if err := ValidateCallbackURL(*callbackURL); err != nil {
			t.Fatalf("unexpected error for nil callback: %v", err)
		}
	}

	empty := ""
	callbackURL = &empty
	if callbackURL != nil && *callbackURL != "" {
		t.Fatal("empty pointer field should have been skipped by the caller guard")
	}
}

// TestRequestValidate_CallbackURL exercises the wired call sites on the request
// types: an empty/unset callback is allowed through, an https one passes, and a
// dangerous one is rejected.
func TestRequestValidate_CallbackURL(t *testing.T) {
	tholdHash := strings.Repeat("a", TholdHashLength)
	bad := "http://127.0.0.1/cb"
	good := "https://regulator.ducatprotocol.com/cb"

	// HttpRequestData: nil callback allowed
	r := &HttpRequestData{Domain: "test", TholdHash: &tholdHash}
	if err := r.Validate(); err != nil {
		t.Fatalf("HttpRequestData with nil callback should pass, got %v", err)
	}
	// HttpRequestData: good callback allowed
	r.CallbackURL = &good
	if err := r.Validate(); err != nil {
		t.Fatalf("HttpRequestData with https callback should pass, got %v", err)
	}
	// HttpRequestData: bad callback rejected
	r.CallbackURL = &bad
	if err := r.Validate(); err == nil {
		t.Fatal("HttpRequestData with loopback http callback should be rejected")
	}

	// EvaluateQuotesRequest
	er := &EvaluateQuotesRequest{TholdHashes: []string{tholdHash}}
	if err := er.Validate(); err != nil {
		t.Fatalf("EvaluateQuotesRequest with nil callback should pass, got %v", err)
	}
	er.CallbackURL = &bad
	if err := er.Validate(); err == nil {
		t.Fatal("EvaluateQuotesRequest with loopback http callback should be rejected")
	}

	// GenerateQuotesRequest
	gr := &GenerateQuotesRequest{RateMin: 1.35, RateMax: 4.0, StepSize: 0.05, Domain: "test"}
	if err := gr.Validate(); err != nil {
		t.Fatalf("GenerateQuotesRequest with nil callback should pass, got %v", err)
	}
	gr.CallbackURL = &bad
	if err := gr.Validate(); err == nil {
		t.Fatal("GenerateQuotesRequest with loopback http callback should be rejected")
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
