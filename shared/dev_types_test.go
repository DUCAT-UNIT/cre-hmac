package shared

import (
	"encoding/json"
	"math"
	"testing"
)

// Tests for dev workflow types and validation
// These types are defined in hmac-dev but we test the logic patterns here

// PriceAdjustmentControl mirrors the dev type for testing
type PriceAdjustmentControl struct {
	Pct       float64 `json:"pct"`
	ExpiresAt int64   `json:"expires_at"`
	SetAt     int64   `json:"set_at"`
}

func (a *PriceAdjustmentControl) IsActive(currentTime int64) bool {
	return a.Pct != 0 && currentTime < a.ExpiresAt
}

// =============================================================================
// Control State Tests
// =============================================================================

func TestDevAdjustmentControlIsActive(t *testing.T) {
	tests := []struct {
		name        string
		pct         float64
		expiresAt   int64
		currentTime int64
		wantActive  bool
	}{
		{"active: future expiry", 5.0, 2000, 1000, true},
		{"active: negative pct", -10.0, 2000, 1000, true},
		{"inactive: past expiry", 5.0, 500, 1000, false},
		{"inactive: exact expiry", 5.0, 1000, 1000, false},
		{"inactive: zero pct", 0, 2000, 1000, false},
		{"inactive: zero pct past", 0, 500, 1000, false},
		{"active: barely before expiry", 1.0, 1001, 1000, true},
		{"inactive: barely after expiry", 1.0, 999, 1000, false},
		{"active: large positive", 500.0, 9999999999, 1000, true},
		{"active: small negative", -0.01, 2000, 1000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := &PriceAdjustmentControl{Pct: tt.pct, ExpiresAt: tt.expiresAt, SetAt: 0}
			if got := c.IsActive(tt.currentTime); got != tt.wantActive {
				t.Errorf("IsActive(%d) = %v, want %v", tt.currentTime, got, tt.wantActive)
			}
		})
	}
}

func TestDevAdjustmentControlJSON(t *testing.T) {
	original := PriceAdjustmentControl{
		Pct:       -15.5,
		ExpiresAt: 1700003600,
		SetAt:     1700000000,
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	// Verify JSON structure
	var raw map[string]interface{}
	json.Unmarshal(data, &raw)

	if _, ok := raw["pct"]; !ok {
		t.Error("JSON should contain 'pct' field")
	}
	if _, ok := raw["expires_at"]; !ok {
		t.Error("JSON should contain 'expires_at' field")
	}
	if _, ok := raw["set_at"]; !ok {
		t.Error("JSON should contain 'set_at' field")
	}

	// Roundtrip
	var decoded PriceAdjustmentControl
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Pct != original.Pct {
		t.Errorf("Pct = %f, want %f", decoded.Pct, original.Pct)
	}
	if decoded.ExpiresAt != original.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", decoded.ExpiresAt, original.ExpiresAt)
	}
	if decoded.SetAt != original.SetAt {
		t.Errorf("SetAt = %d, want %d", decoded.SetAt, original.SetAt)
	}
}

// =============================================================================
// Price Adjustment Calculation Tests
// =============================================================================

func TestDevPriceAdjustmentCalculation(t *testing.T) {
	tests := []struct {
		name      string
		basePrice float64
		pct       float64
		wantPrice float64
	}{
		{"no change", 100000, 0, 100000},
		{"+5%", 100000, 5.0, 105000},
		{"-5%", 100000, -5.0, 95000},
		{"+10%", 100000, 10.0, 110000},
		{"-10%", 100000, -10.0, 90000},
		{"+50%", 100000, 50.0, 150000},
		{"-50%", 100000, -50.0, 50000},
		{"+100%", 100000, 100.0, 200000},
		{"-99%", 100000, -99.0, 1000},
		{"+0.1%", 100000, 0.1, 100100},
		{"-0.1%", 100000, -0.1, 99900},
		{"large base +5%", 500000, 5.0, 525000},
		{"small base -20%", 10000, -20.0, 8000},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adjusted := tt.basePrice * (1 + tt.pct/100)
			if math.Abs(adjusted-tt.wantPrice) > 0.01 {
				t.Errorf("%.0f * (1 + %.2f/100) = %.6f, want %.6f", tt.basePrice, tt.pct, adjusted, tt.wantPrice)
			}
		})
	}
}

// =============================================================================
// Duration Calculation Tests
// =============================================================================

func TestDevDurationToExpiry(t *testing.T) {
	tests := []struct {
		name            string
		setAt           int64
		durationMinutes int
		wantExpiresAt   int64
	}{
		{"30 minutes", 1700000000, 30, 1700001800},
		{"60 minutes", 1700000000, 60, 1700003600},
		{"1 minute", 1700000000, 1, 1700000060},
		{"1440 minutes (24h)", 1700000000, 1440, 1700086400},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expiresAt := tt.setAt + int64(tt.durationMinutes*60)
			if expiresAt != tt.wantExpiresAt {
				t.Errorf("ExpiresAt = %d, want %d", expiresAt, tt.wantExpiresAt)
			}
		})
	}
}

// =============================================================================
// Adjusted Price Bounds Tests
// =============================================================================

func TestDevAdjustedPriceBounds(t *testing.T) {
	// Verify adjusted prices stay within reasonable bounds
	tests := []struct {
		name      string
		basePrice float64
		pct       float64
		wantValid bool
	}{
		{"normal +5%", 100000, 5.0, true},
		{"normal -15%", 100000, -15.0, true},
		{"-99% still above min", 100000, -99.0, true}, // 1000, at MinReasonablePrice
		{"-99% from low", 2000, -99.0, false},         // 20, below min
		{"+500% from high", 200000, 500.0, false},     // 1200000, above max
		{"+50% within range", 200000, 50.0, true},     // 300000
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adjusted := tt.basePrice * (1 + tt.pct/100)
			valid := adjusted >= MinReasonablePrice && adjusted <= MaxReasonablePrice
			if valid != tt.wantValid {
				t.Errorf("Price %.0f with %+.0f%% = %.0f, valid=%v want=%v", tt.basePrice, tt.pct, adjusted, valid, tt.wantValid)
			}
		})
	}
}

// =============================================================================
// Nostr Event d-tag Tests
// =============================================================================

func TestDevControlEventDTag(t *testing.T) {
	// The control event uses a specific d-tag that should not collide with quote hashes
	controlDTag := "price_adjustment_control"

	// Must not be a valid thold hash (40 hex chars)
	if IsValidTholdHash(controlDTag) {
		t.Error("Control d-tag should NOT be a valid thold hash (to avoid collisions)")
	}

	// Must be a valid domain-like string (for the d-tag)
	if controlDTag == "" {
		t.Error("Control d-tag should not be empty")
	}
}

func TestDevQuoteEventDTagUsesTholdHashFormat(t *testing.T) {
	quoteDTag := "0123456789abcdef0123456789abcdef01234567"
	if !IsValidTholdHash(quoteDTag) {
		t.Error("Quote d-tag should be a valid thold hash (40 hex chars)")
	}

	legacyCommitHashDTag := "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	if IsValidTholdHash(legacyCommitHashDTag) {
		t.Error("Legacy commit-hash d-tag (64 hex chars) should not validate as thold hash")
	}
}
