package wasmtest

import (
	"encoding/json"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"ducat/crypto"
	"ducat/shared"
)

// =============================================================================
// Price Adjustment Types (mirrors hmac-dev/types.go for testing)
// =============================================================================

const AdjustmentControlDTag = "price_adjustment_control"

type PriceAdjustmentControl struct {
	Pct       float64 `json:"pct"`
	ExpiresAt int64   `json:"expires_at"`
	SetAt     int64   `json:"set_at"`
}

func (a *PriceAdjustmentControl) IsActive(currentTime int64) bool {
	return a.Pct != 0 && currentTime < a.ExpiresAt
}

type PriceAdjustmentRequest struct {
	Pct             float64 `json:"pct"`
	DurationMinutes int     `json:"duration_minutes"`
}

func (r *PriceAdjustmentRequest) Validate() error {
	if r == nil {
		return fmt.Errorf("request is nil")
	}
	if r.Pct < -50 || r.Pct > 50 {
		return fmt.Errorf("pct must be between -50 and 50, got %.2f", r.Pct)
	}
	if r.DurationMinutes <= 0 {
		return fmt.Errorf("duration_minutes must be positive, got %d", r.DurationMinutes)
	}
	if r.DurationMinutes > 5 {
		return fmt.Errorf("duration_minutes cannot exceed 5, got %d", r.DurationMinutes)
	}
	return nil
}

// =============================================================================
// Dev Workflow Simulator
// =============================================================================

// DevWorkflowSimulator extends the base simulator with adjustment capabilities
type DevWorkflowSimulator struct {
	*WorkflowSimulator
	adjustment *PriceAdjustmentControl // active adjustment
}

// NewDevWorkflowSimulator creates a dev simulator with adjustment support
func NewDevWorkflowSimulator(privateKey string) *DevWorkflowSimulator {
	return &DevWorkflowSimulator{
		WorkflowSimulator: NewWorkflowSimulator(privateKey),
	}
}

// SetAdjustment simulates the "adjust" action
func (d *DevWorkflowSimulator) SetAdjustment(pct float64, durationMinutes int) error {
	req := &PriceAdjustmentRequest{Pct: pct, DurationMinutes: durationMinutes}
	if err := req.Validate(); err != nil {
		return err
	}

	currentStamp := d.PriceClient.Stamp
	d.adjustment = &PriceAdjustmentControl{
		Pct:       pct,
		ExpiresAt: currentStamp + int64(durationMinutes*60),
		SetAt:     currentStamp,
	}

	// Store as a Nostr event on the relay (simulating relay state)
	kd, err := crypto.DeriveKeys(d.PrivateKey)
	if err != nil {
		return fmt.Errorf("key derivation failed: %w", err)
	}

	controlJSON, _ := json.Marshal(d.adjustment)
	event := &shared.NostrEvent{
		PubKey:    kd.SchnorrPubkey,
		CreatedAt: currentStamp,
		Kind:      shared.NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", AdjustmentControlDTag},
			{"domain", "dev-control"},
		},
		Content: string(controlJSON),
	}
	signNostrEvent(event, kd.PrivateKey)
	d.RelayClient.PublishEvent(event)

	return nil
}

// ClearAdjustment simulates the "clear_adjust" action
func (d *DevWorkflowSimulator) ClearAdjustment() {
	currentStamp := d.PriceClient.Stamp
	d.adjustment = &PriceAdjustmentControl{
		Pct:       0,
		ExpiresAt: currentStamp, // already expired
		SetAt:     currentStamp,
	}

	// Update relay
	kd, _ := crypto.DeriveKeys(d.PrivateKey)
	controlJSON, _ := json.Marshal(d.adjustment)
	event := &shared.NostrEvent{
		PubKey:    kd.SchnorrPubkey,
		CreatedAt: currentStamp,
		Kind:      shared.NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", AdjustmentControlDTag},
			{"domain", "dev-control"},
		},
		Content: string(controlJSON),
	}
	signNostrEvent(event, kd.PrivateKey)
	d.RelayClient.PublishEvent(event)
}

// GetActiveAdjustment returns the effective price after adjustment
func (d *DevWorkflowSimulator) GetAdjustedPrice() (float64, bool) {
	basePrice := d.PriceClient.Price
	if d.adjustment == nil || !d.adjustment.IsActive(d.PriceClient.Stamp) {
		return basePrice, false
	}
	adjusted := basePrice * (1 + d.adjustment.Pct/100)
	return adjusted, true
}

// SimulateCreateQuoteDev creates a quote using the adjusted price
func (d *DevWorkflowSimulator) SimulateCreateQuoteDev(domain string, tholdPrice float64) (*shared.NostrEvent, error) {
	effectivePrice, adjusted := d.GetAdjustedPrice()

	// Temporarily set price client to effective price
	origPrice := d.PriceClient.Price
	d.PriceClient.Price = effectivePrice
	defer func() { d.PriceClient.Price = origPrice }()

	event, err := d.SimulateCreateQuote(domain, tholdPrice)
	if err != nil {
		return nil, err
	}

	if adjusted {
		// Log that adjustment was applied
		d.Logger.Info("Created quote with adjusted price", "original", origPrice, "adjusted", effectivePrice, "pct", d.adjustment.Pct)
	}

	return event, nil
}

// SimulateGenerateQuotesDev generates quotes using the adjusted price
func (d *DevWorkflowSimulator) SimulateGenerateQuotesDev(req *shared.GenerateQuotesRequest) (*shared.GenerateQuotesResponse, error) {
	effectivePrice, _ := d.GetAdjustedPrice()

	origPrice := d.PriceClient.Price
	d.PriceClient.Price = effectivePrice
	defer func() { d.PriceClient.Price = origPrice }()

	return d.SimulateGenerateQuotes(req)
}

// SimulateEvaluateQuotesDev evaluates quotes using the adjusted price
func (d *DevWorkflowSimulator) SimulateEvaluateQuotesDev(tholdHashes []string) (*shared.EvaluateQuotesResponse, error) {
	effectivePrice, _ := d.GetAdjustedPrice()

	origPrice := d.PriceClient.Price
	d.PriceClient.Price = effectivePrice
	defer func() { d.PriceClient.Price = origPrice }()

	return d.SimulateEvaluateQuotes(tholdHashes)
}

// =============================================================================
// Adjustment Request Validation Tests
// =============================================================================

func TestPriceAdjustmentRequestValidation(t *testing.T) {
	tests := []struct {
		name       string
		pct        float64
		duration   int
		wantErr    bool
		errContain string
	}{
		{"valid positive adjustment", 5.0, 3, false, ""},
		{"valid negative adjustment", -10.0, 5, false, ""},
		{"valid zero pct", 0, 1, false, ""},
		{"valid max pct", 50.0, 5, false, ""},
		{"valid min pct", -50.0, 5, false, ""},
		{"pct too low", -50.01, 3, true, "pct must be between"},
		{"pct too high", 50.01, 3, true, "pct must be between"},
		{"zero duration", 5.0, 0, true, "duration_minutes must be positive"},
		{"negative duration", 5.0, -1, true, "duration_minutes must be positive"},
		{"duration too long", 5.0, 6, true, "duration_minutes cannot exceed"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &PriceAdjustmentRequest{Pct: tt.pct, DurationMinutes: tt.duration}
			err := req.Validate()
			if tt.wantErr {
				if err == nil {
					t.Error("Expected error, got nil")
				} else if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContain)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPriceAdjustmentRequestValidateNil(t *testing.T) {
	var req *PriceAdjustmentRequest
	if err := req.Validate(); err == nil {
		t.Error("Expected error for nil request")
	}
}

// =============================================================================
// Adjustment Control State Tests
// =============================================================================

func TestPriceAdjustmentControlIsActive(t *testing.T) {
	tests := []struct {
		name        string
		pct         float64
		expiresAt   int64
		currentTime int64
		wantActive  bool
	}{
		{"active: not expired", 5.0, 1700002000, 1700001000, true},
		{"active: negative pct", -10.0, 1700002000, 1700001000, true},
		{"inactive: expired", 5.0, 1700000000, 1700001000, false},
		{"inactive: exactly at expiry", 5.0, 1700001000, 1700001000, false},
		{"inactive: zero pct", 0, 1700002000, 1700001000, false},
		{"inactive: zero pct expired", 0, 1700000000, 1700001000, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			control := &PriceAdjustmentControl{
				Pct:       tt.pct,
				ExpiresAt: tt.expiresAt,
				SetAt:     1700000000,
			}
			if got := control.IsActive(tt.currentTime); got != tt.wantActive {
				t.Errorf("IsActive(%d) = %v, want %v", tt.currentTime, got, tt.wantActive)
			}
		})
	}
}

func TestAdjustmentControlJSONRoundtrip(t *testing.T) {
	control := PriceAdjustmentControl{
		Pct:       -15.5,
		ExpiresAt: 1700003600,
		SetAt:     1700000000,
	}

	data, err := json.Marshal(control)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}

	var decoded PriceAdjustmentControl
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}

	if decoded.Pct != control.Pct {
		t.Errorf("Pct = %f, want %f", decoded.Pct, control.Pct)
	}
	if decoded.ExpiresAt != control.ExpiresAt {
		t.Errorf("ExpiresAt = %d, want %d", decoded.ExpiresAt, control.ExpiresAt)
	}
	if decoded.SetAt != control.SetAt {
		t.Errorf("SetAt = %d, want %d", decoded.SetAt, control.SetAt)
	}
}

// =============================================================================
// Set Adjustment Tests
// =============================================================================

func TestSetAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	err := sim.SetAdjustment(-15.0, 5)
	if err != nil {
		t.Fatalf("SetAdjustment failed: %v", err)
	}

	// Verify adjustment is stored
	if sim.adjustment == nil {
		t.Fatal("Adjustment should be set")
	}
	if sim.adjustment.Pct != -15.0 {
		t.Errorf("Pct = %f, want -15.0", sim.adjustment.Pct)
	}
	if sim.adjustment.ExpiresAt != 1700000000+300 {
		t.Errorf("ExpiresAt = %d, want %d", sim.adjustment.ExpiresAt, 1700000000+300)
	}

	// Verify control event published to relay
	event, err := sim.RelayClient.FetchByDTag(AdjustmentControlDTag)
	if err != nil {
		t.Fatalf("Control event not found on relay: %v", err)
	}

	var storedControl PriceAdjustmentControl
	json.Unmarshal([]byte(event.Content), &storedControl)
	if storedControl.Pct != -15.0 {
		t.Errorf("Stored Pct = %f, want -15.0", storedControl.Pct)
	}
}

func TestSetAdjustmentValidation(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Invalid: pct too low (duration valid, so only pct triggers rejection)
	err := sim.SetAdjustment(-100, 3)
	if err == nil {
		t.Error("Expected error for pct=-100")
	}

	// Invalid: duration too long
	err = sim.SetAdjustment(5, 2000)
	if err == nil {
		t.Error("Expected error for duration=2000")
	}
}

func TestClearAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set, then clear
	sim.SetAdjustment(-15.0, 5)
	sim.ClearAdjustment()

	// Adjustment should no longer be active
	_, adjusted := sim.GetAdjustedPrice()
	if adjusted {
		t.Error("Adjustment should be inactive after clear")
	}
}

// =============================================================================
// Adjusted Price Calculation Tests
// =============================================================================

func TestGetAdjustedPrice(t *testing.T) {
	tests := []struct {
		name         string
		basePrice    float64
		pct          float64
		duration     int
		stamp        int64
		wantPrice    float64
		wantAdjusted bool
	}{
		{"no adjustment", 100000, 0, 0, 1700000000, 100000, false},
		{"+5%", 100000, 5.0, 5, 1700000000, 105000, true},
		{"-15%", 100000, -15.0, 5, 1700000000, 85000, true},
		{"+50%", 100000, 50.0, 3, 1700000000, 150000, true},
		{"-50%", 100000, -50.0, 3, 1700000000, 50000, true},
		{"+0.5%", 100000, 0.5, 1, 1700000000, 100500, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := NewDevWorkflowSimulator(testPrivateKey)
			sim.PriceClient.Price = tt.basePrice
			sim.PriceClient.Stamp = tt.stamp

			if tt.pct != 0 {
				sim.SetAdjustment(tt.pct, tt.duration)
			}

			price, adjusted := sim.GetAdjustedPrice()
			if adjusted != tt.wantAdjusted {
				t.Errorf("adjusted = %v, want %v", adjusted, tt.wantAdjusted)
			}
			if math.Abs(price-tt.wantPrice) > 0.01 {
				t.Errorf("price = %f, want %f", price, tt.wantPrice)
			}
		})
	}
}

func TestAdjustmentExpiry(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set 3 minute adjustment
	sim.SetAdjustment(-15.0, 3)

	// Before expiry: adjusted
	price, adjusted := sim.GetAdjustedPrice()
	if !adjusted {
		t.Error("Should be adjusted before expiry")
	}
	if math.Abs(price-85000) > 0.01 {
		t.Errorf("Price = %f, want 85000", price)
	}

	// Advance time past expiry (3 minutes = 180 seconds)
	sim.PriceClient.Stamp = 1700000000 + 181

	// After expiry: not adjusted
	price, adjusted = sim.GetAdjustedPrice()
	if adjusted {
		t.Error("Should not be adjusted after expiry")
	}
	if price != 100000 {
		t.Errorf("Price = %f, want 100000 (original)", price)
	}
}

func TestAdjustmentExactExpiry(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	sim.SetAdjustment(-15.0, 3)

	// Exactly at expiry: NOT active (ExpiresAt is exclusive)
	sim.PriceClient.Stamp = 1700000000 + 180
	_, adjusted := sim.GetAdjustedPrice()
	if adjusted {
		t.Error("Should not be adjusted at exact expiry time")
	}

	// One second before expiry: still active
	sim.PriceClient.Stamp = 1700000000 + 179
	_, adjusted = sim.GetAdjustedPrice()
	if !adjusted {
		t.Error("Should be adjusted 1 second before expiry")
	}
}

// =============================================================================
// Quote Creation with Adjustment Tests
// =============================================================================

func TestCreateQuoteWithPositiveAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set +10% adjustment
	sim.SetAdjustment(10.0, 5)

	// Create quote — base price should be 110000 (100000 + 10%)
	event, err := sim.SimulateCreateQuoteDev("test-dev", 95000)
	if err != nil {
		t.Fatalf("CreateQuote failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	// The quote price should reflect the adjusted price
	if math.Abs(data.QuotePrice-110000) > 0.01 {
		t.Errorf("QuotePrice = %f, want 110000 (adjusted +10%%)", data.QuotePrice)
	}

	// Nostr event should be valid
	if err := verifyNostrEvent(event); err != nil {
		t.Errorf("Event verification failed: %v", err)
	}
}

func TestCreateQuoteWithNegativeAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set -20% adjustment
	sim.SetAdjustment(-20.0, 5)

	// Effective price is 80000, threshold at 70000 (below)
	event, err := sim.SimulateCreateQuoteDev("test-dev", 70000)
	if err != nil {
		t.Fatalf("CreateQuote failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	if math.Abs(data.QuotePrice-80000) > 0.01 {
		t.Errorf("QuotePrice = %f, want 80000 (adjusted -20%%)", data.QuotePrice)
	}
}

func TestCreateQuoteWithoutAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// No adjustment set — should behave like production
	event, err := sim.SimulateCreateQuoteDev("test-dev", 90000)
	if err != nil {
		t.Fatalf("CreateQuote failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	if data.QuotePrice != 100000 {
		t.Errorf("QuotePrice = %f, want 100000 (no adjustment)", data.QuotePrice)
	}
}

func TestCreateQuoteAfterAdjustmentExpires(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set short adjustment
	sim.SetAdjustment(-20.0, 5) // 5 minutes

	// Advance past expiry
	sim.PriceClient.Stamp = 1700000000 + 301

	event, err := sim.SimulateCreateQuoteDev("test-dev", 90000)
	if err != nil {
		t.Fatalf("CreateQuote failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	// Should use real price (adjustment expired)
	if data.QuotePrice != 100000 {
		t.Errorf("QuotePrice = %f, want 100000 (adjustment expired)", data.QuotePrice)
	}
}

// =============================================================================
// Quote Evaluation with Adjustment Tests
// =============================================================================

func TestEvaluateQuotesWithAdjustmentCausingBreach(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create quotes at normal price (threshold at 90000)
	event, err := sim.SimulateCreateQuoteDev("test-dev", 90000)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	// Now apply -15% adjustment (price becomes 85000, below 90000 threshold)
	sim.SetAdjustment(-15.0, 5)

	// Evaluate — should breach
	response, err := sim.SimulateEvaluateQuotesDev([]string{data.TholdHash})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if len(response.Results) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(response.Results))
	}

	if response.Results[0].Status != "breached" {
		t.Errorf("Status = %q, want 'breached' (adjusted price 85000 < threshold 90000)", response.Results[0].Status)
	}
	if response.Results[0].TholdKey == nil {
		t.Error("TholdKey should be revealed on breach")
	}

	// Verify current price reflects adjustment
	if math.Abs(response.CurrentPrice-85000) > 0.01 {
		t.Errorf("CurrentPrice = %f, want 85000", response.CurrentPrice)
	}
}

func TestEvaluateQuotesWithoutAdjustmentNoBreach(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	event, err := sim.SimulateCreateQuoteDev("test-dev", 90000)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	// No adjustment — price at 100000, threshold at 90000 — should be active
	response, err := sim.SimulateEvaluateQuotesDev([]string{data.TholdHash})
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}

	if response.Results[0].Status != "active" {
		t.Errorf("Status = %q, want 'active'", response.Results[0].Status)
	}
}

// =============================================================================
// Quote Generation with Adjustment Tests
// =============================================================================

func TestGenerateQuotesWithAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set +20% adjustment (price becomes 120000)
	sim.SetAdjustment(20.0, 5)

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     1.50,
		StepSize:    0.05,
		Domain:      "gen-dev",
		QuoteDomain: "auto-dev",
	}

	response, err := sim.SimulateGenerateQuotesDev(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Price should be adjusted
	if math.Abs(response.CurrentPrice-120000) > 0.01 {
		t.Errorf("CurrentPrice = %f, want 120000 (adjusted +20%%)", response.CurrentPrice)
	}

	if response.QuotesCreated < 3 {
		t.Errorf("Expected at least 3 quotes, got %d", response.QuotesCreated)
	}

	// Verify threshold range is based on adjusted price
	expectedMinThold := 120000 * 1.35
	if response.Range.MinThold < expectedMinThold*0.99 || response.Range.MinThold > expectedMinThold*1.01 {
		t.Errorf("MinThold = %f, expected ~%f (based on adjusted price)", response.Range.MinThold, expectedMinThold)
	}
}

func TestGenerateQuotesWithNoAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     1.50,
		StepSize:    0.05,
		Domain:      "gen-dev",
		QuoteDomain: "auto-dev",
	}

	response, err := sim.SimulateGenerateQuotesDev(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	if response.CurrentPrice != 100000 {
		t.Errorf("CurrentPrice = %f, want 100000 (no adjustment)", response.CurrentPrice)
	}
}

// =============================================================================
// Adjustment Overwrite Tests
// =============================================================================

func TestOverwriteAdjustment(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// First adjustment: -10%
	sim.SetAdjustment(-10.0, 5)
	price, _ := sim.GetAdjustedPrice()
	if math.Abs(price-90000) > 0.01 {
		t.Errorf("First adjustment: price = %f, want 90000", price)
	}

	// Overwrite with +5%
	sim.SetAdjustment(5.0, 3)
	price, _ = sim.GetAdjustedPrice()
	if math.Abs(price-105000) > 0.01 {
		t.Errorf("Second adjustment: price = %f, want 105000", price)
	}
}

func TestSetThenClearThenSet(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set
	sim.SetAdjustment(-20.0, 5)
	price, adjusted := sim.GetAdjustedPrice()
	if !adjusted || math.Abs(price-80000) > 0.01 {
		t.Errorf("After set: price=%f adjusted=%v, want 80000/true", price, adjusted)
	}

	// Clear
	sim.ClearAdjustment()
	price, adjusted = sim.GetAdjustedPrice()
	if adjusted || math.Abs(price-100000) > 0.01 {
		t.Errorf("After clear: price=%f adjusted=%v, want 100000/false", price, adjusted)
	}

	// Set again
	sim.SetAdjustment(10.0, 3)
	price, adjusted = sim.GetAdjustedPrice()
	if !adjusted || math.Abs(price-110000) > 0.01 {
		t.Errorf("After re-set: price=%f adjusted=%v, want 110000/true", price, adjusted)
	}
}

// =============================================================================
// Control Event Relay Storage Tests
// =============================================================================

func TestControlEventStoredOnRelay(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	sim.SetAdjustment(-15.0, 4)

	// Fetch the control event from the relay
	event, err := sim.RelayClient.FetchByDTag(AdjustmentControlDTag)
	if err != nil {
		t.Fatalf("Control event not on relay: %v", err)
	}

	// Verify Nostr event structure
	if event.Kind != shared.NostrEventKindThresholdCommitment {
		t.Errorf("Kind = %d, want %d", event.Kind, shared.NostrEventKindThresholdCommitment)
	}

	dTag := event.GetTag("d")
	if dTag != AdjustmentControlDTag {
		t.Errorf("d-tag = %q, want %q", dTag, AdjustmentControlDTag)
	}

	domainTag := event.GetTag("domain")
	if domainTag != "dev-control" {
		t.Errorf("domain tag = %q, want 'dev-control'", domainTag)
	}

	// Verify content parses as PriceAdjustmentControl
	var control PriceAdjustmentControl
	if err := json.Unmarshal([]byte(event.Content), &control); err != nil {
		t.Fatalf("Failed to parse control content: %v", err)
	}
	if control.Pct != -15.0 {
		t.Errorf("Pct = %f, want -15.0", control.Pct)
	}
	if control.ExpiresAt != 1700000000+240 {
		t.Errorf("ExpiresAt = %d, want %d", control.ExpiresAt, 1700000000+240)
	}

	// Verify Nostr signature
	if err := verifyNostrEvent(event); err != nil {
		t.Errorf("Control event signature invalid: %v", err)
	}
}

func TestControlEventReplacedOnOverwrite(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// First adjustment
	sim.SetAdjustment(-10.0, 3)

	// Overwrite
	sim.SetAdjustment(5.0, 5)

	// The relay stores by d-tag, so the latest should win
	event, _ := sim.RelayClient.FetchByDTag(AdjustmentControlDTag)
	var control PriceAdjustmentControl
	json.Unmarshal([]byte(event.Content), &control)

	if control.Pct != 5.0 {
		t.Errorf("Pct = %f, want 5.0 (overwritten)", control.Pct)
	}
}

// =============================================================================
// End-to-End Dev Workflow Tests
// =============================================================================

func TestDevWorkflowFullCycle(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// 1. Create quotes at normal price
	event1, err := sim.SimulateCreateQuoteDev("cycle-test", 90000)
	if err != nil {
		t.Fatalf("Step 1 create failed: %v", err)
	}
	var data1 shared.PriceEvent
	json.Unmarshal([]byte(event1.Content), &data1)

	// 2. Verify quote is active
	resp1, err := sim.SimulateEvaluateQuotesDev([]string{data1.TholdHash})
	if err != nil {
		t.Fatalf("Step 2 evaluate failed: %v", err)
	}
	if resp1.Results[0].Status != "active" {
		t.Errorf("Step 2: expected active, got %q", resp1.Results[0].Status)
	}

	// 3. Set -15% adjustment (price becomes 85000, below 90000 threshold)
	sim.SetAdjustment(-15.0, 5)

	// 4. Evaluate again — should now breach
	resp2, err := sim.SimulateEvaluateQuotesDev([]string{data1.TholdHash})
	if err != nil {
		t.Fatalf("Step 4 evaluate failed: %v", err)
	}
	if resp2.Results[0].Status != "breached" {
		t.Errorf("Step 4: expected breached, got %q", resp2.Results[0].Status)
	}

	// 5. Clear adjustment
	sim.ClearAdjustment()

	// 6. Create new quote at real price
	event2, err := sim.SimulateCreateQuoteDev("cycle-test-2", 90000)
	if err != nil {
		t.Fatalf("Step 6 create failed: %v", err)
	}
	var data2 shared.PriceEvent
	json.Unmarshal([]byte(event2.Content), &data2)

	if data2.QuotePrice != 100000 {
		t.Errorf("Step 6: QuotePrice = %f, want 100000 (adjustment cleared)", data2.QuotePrice)
	}
}

func TestDevWorkflowAdjustmentDuringGeneration(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Set -30% adjustment
	sim.SetAdjustment(-30.0, 5)

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     2.0,
		StepSize:    0.05,
		Domain:      "gen-cycle",
		QuoteDomain: "auto-cycle",
	}

	response, err := sim.SimulateGenerateQuotesDev(req)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Price should be 70000 (-30%)
	if math.Abs(response.CurrentPrice-70000) > 0.01 {
		t.Errorf("CurrentPrice = %f, want 70000", response.CurrentPrice)
	}

	// All generated quotes should use the adjusted price as base
	for _, hash := range response.TholdHashes {
		event, err := sim.RelayClient.FetchByDTag(hash)
		if err != nil {
			t.Errorf("Failed to fetch quote %s: %v", hash[:8], err)
			continue
		}
		var data shared.PriceEvent
		json.Unmarshal([]byte(event.Content), &data)
		if math.Abs(data.QuotePrice-70000) > 0.01 {
			t.Errorf("Quote %s has QuotePrice=%f, want 70000", hash[:8], data.QuotePrice)
		}
	}
}

// =============================================================================
// Concurrent Adjustment Tests
// =============================================================================

func TestConcurrentAdjustmentAndQuoteCreation(t *testing.T) {
	// Each goroutine gets its own simulator to avoid shared PriceClient mutation,
	// mirroring real CRE behavior where each invocation fetches a fresh price.
	numQuotes := 20
	var wg sync.WaitGroup
	events := make([]*shared.NostrEvent, numQuotes)
	errors := make([]error, numQuotes)

	for i := 0; i < numQuotes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			sim := NewDevWorkflowSimulator(testPrivateKey)
			sim.PriceClient.Price = 100000
			sim.PriceClient.Stamp = 1700000000
			sim.SetAdjustment(-10.0, 5)
			tholdPrice := 80000.0 - float64(idx*100)
			events[idx], errors[idx] = sim.SimulateCreateQuoteDev(fmt.Sprintf("concurrent-%d", idx), tholdPrice)
		}(i)
	}

	wg.Wait()

	successCount := 0
	for i := 0; i < numQuotes; i++ {
		if errors[i] == nil {
			successCount++
		}
	}

	if successCount < numQuotes {
		t.Errorf("Expected all %d quotes to succeed, got %d", numQuotes, successCount)
	}

	// All should use the adjusted price (90000)
	for i, event := range events {
		if event != nil {
			var data shared.PriceEvent
			json.Unmarshal([]byte(event.Content), &data)
			if math.Abs(data.QuotePrice-90000) > 0.01 {
				t.Errorf("Quote %d QuotePrice = %f, want 90000 (adjusted -10%%)", i, data.QuotePrice)
			}
		}
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestAdjustmentBoundaryPct(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Test boundary: -50% (H5 floor for the adjustment control)
	sim.SetAdjustment(-50.0, 3)
	price, adjusted := sim.GetAdjustedPrice()
	if !adjusted {
		t.Error("Should be adjusted at -50%")
	}
	if math.Abs(price-50000) > 0.01 {
		t.Errorf("Price at -50%% = %f, want 50000", price)
	}

	// Test boundary: +50% (H5 ceiling for the adjustment control)
	sim.SetAdjustment(50.0, 3)
	price, _ = sim.GetAdjustedPrice()
	if math.Abs(price-150000) > 0.01 {
		t.Errorf("Price at +50%% = %f, want 150000", price)
	}
}

func TestAdjustmentSmallPct(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	sim.SetAdjustment(0.01, 3) // +0.01%
	price, adjusted := sim.GetAdjustedPrice()
	if !adjusted {
		t.Error("Should be adjusted")
	}
	expectedPrice := 100000 * 1.0001
	if math.Abs(price-expectedPrice) > 0.01 {
		t.Errorf("Price = %f, want %f", price, expectedPrice)
	}
}

func TestAdjustmentWithMinDuration(t *testing.T) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	sim.SetAdjustment(-5.0, 1) // 1 minute

	// Active within 1 minute
	_, adjusted := sim.GetAdjustedPrice()
	if !adjusted {
		t.Error("Should be active within 1 minute")
	}

	// Expired after 1 minute
	sim.PriceClient.Stamp = 1700000000 + 61
	_, adjusted = sim.GetAdjustedPrice()
	if adjusted {
		t.Error("Should be expired after 1 minute")
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkDevCreateQuoteWithAdjustment(b *testing.B) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000
	sim.SetAdjustment(-15.0, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sim.SimulateCreateQuoteDev("bench", 70000)
	}
}

func BenchmarkDevGetAdjustedPrice(b *testing.B) {
	sim := NewDevWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000
	sim.SetAdjustment(-15.0, 5)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sim.GetAdjustedPrice()
	}
}
