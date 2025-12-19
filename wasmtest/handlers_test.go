package wasmtest

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"ducat/crypto"
	"ducat/shared"
)

const testPrivateKey = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"

// =============================================================================
// CreateQuote Handler Tests
// =============================================================================

func TestSimulateCreateQuote(t *testing.T) {
	tests := []struct {
		name       string
		domain     string
		tholdPrice float64
		price      float64
		wantErr    bool
		errContain string
	}{
		{
			name:       "valid downside protection",
			domain:     "test-domain",
			tholdPrice: 90000.0,
			price:      100000.0,
			wantErr:    false,
		},
		{
			name:       "valid upside trigger",
			domain:     "test-domain",
			tholdPrice: 110000.0,
			price:      100000.0,
			wantErr:    false,
		},
		{
			name:       "threshold too close below",
			domain:     "test-domain",
			tholdPrice: 99500.0, // Only 0.5% below
			price:      100000.0,
			wantErr:    true,
			errContain: "too close",
		},
		{
			name:       "threshold too close above",
			domain:     "test-domain",
			tholdPrice: 100500.0, // Only 0.5% above
			price:      100000.0,
			wantErr:    true,
			errContain: "too close",
		},
		{
			name:       "large threshold distance",
			domain:     "test-domain",
			tholdPrice: 50000.0, // 50% below
			price:      100000.0,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sim := NewWorkflowSimulator(testPrivateKey)
			sim.PriceClient.Price = tt.price
			sim.PriceClient.Stamp = 1700000000

			event, err := sim.SimulateCreateQuote(tt.domain, tt.tholdPrice)

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if tt.errContain != "" && !strings.Contains(err.Error(), tt.errContain) {
					t.Errorf("Error %q should contain %q", err.Error(), tt.errContain)
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			// Verify event structure
			if event.ID == "" {
				t.Error("Event ID should not be empty")
			}
			if event.PubKey == "" {
				t.Error("Event PubKey should not be empty")
			}
			if event.Sig == "" {
				t.Error("Event Sig should not be empty")
			}
			if event.Kind != shared.NostrEventKindThresholdCommitment {
				t.Errorf("Event Kind = %d, want %d", event.Kind, shared.NostrEventKindThresholdCommitment)
			}

			// Verify Nostr signature
			if err := verifyNostrEvent(event); err != nil {
				t.Errorf("Nostr event verification failed: %v", err)
			}

			// Verify event published to relay
			if len(sim.RelayClient.PublishedEvents) != 1 {
				t.Errorf("Expected 1 published event, got %d", len(sim.RelayClient.PublishedEvents))
			}

			// Verify content
			var priceEvent shared.PriceEvent
			if err := json.Unmarshal([]byte(event.Content), &priceEvent); err != nil {
				t.Fatalf("Failed to parse event content: %v", err)
			}

			if priceEvent.EventType != shared.EventTypeActive {
				t.Errorf("EventType = %q, want %q", priceEvent.EventType, shared.EventTypeActive)
			}
			if priceEvent.TholdPrice != tt.tholdPrice {
				t.Errorf("TholdPrice = %f, want %f", priceEvent.TholdPrice, tt.tholdPrice)
			}
			if priceEvent.TholdKey != nil {
				t.Error("TholdKey should be nil for active quote")
			}

			// Verify crypto fields
			if !shared.IsValidTholdHash(priceEvent.TholdHash) {
				t.Errorf("Invalid TholdHash: %s", priceEvent.TholdHash)
			}
			if !shared.IsValidCommitHash(priceEvent.CommitHash) {
				t.Errorf("Invalid CommitHash: %s", priceEvent.CommitHash)
			}
			if !shared.IsValidContractID(priceEvent.ContractID) {
				t.Errorf("Invalid ContractID: %s", priceEvent.ContractID)
			}
			if !shared.IsValidOracleSig(priceEvent.OracleSig) {
				t.Errorf("Invalid OracleSig: %s", priceEvent.OracleSig)
			}
		})
	}
}

func TestCreateQuotePriceClientError(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Error = fmt.Errorf("network error")

	_, err := sim.SimulateCreateQuote("test-domain", 90000.0)
	if err == nil {
		t.Error("Expected error when price client fails")
	}
	if !strings.Contains(err.Error(), "price fetch failed") {
		t.Errorf("Error should mention price fetch: %v", err)
	}
}

func TestCreateQuoteRelayError(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000
	sim.RelayClient.PublishError = fmt.Errorf("relay unavailable")

	_, err := sim.SimulateCreateQuote("test-domain", 90000.0)
	if err == nil {
		t.Error("Expected error when relay fails")
	}
	if !strings.Contains(err.Error(), "relay publish failed") {
		t.Errorf("Error should mention relay publish: %v", err)
	}
}

// =============================================================================
// CheckQuote Handler Tests
// =============================================================================

func TestSimulateCheckQuoteNotBreached(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create a quote first
	originalEvent, err := sim.SimulateCreateQuote("test-domain", 90000.0)
	if err != nil {
		t.Fatalf("Failed to create quote: %v", err)
	}

	// Get thold_hash from original event
	var originalData shared.PriceEvent
	json.Unmarshal([]byte(originalEvent.Content), &originalData)

	// Check quote - price still above threshold
	resultEvent, err := sim.SimulateCheckQuote("test-domain", originalData.TholdHash)
	if err != nil {
		t.Fatalf("Failed to check quote: %v", err)
	}

	// Should return original event unchanged
	if resultEvent.ID != originalEvent.ID {
		t.Error("Should return original event when not breached")
	}

	var resultData shared.PriceEvent
	json.Unmarshal([]byte(resultEvent.Content), &resultData)

	if resultData.EventType != shared.EventTypeActive {
		t.Errorf("EventType = %q, want %q", resultData.EventType, shared.EventTypeActive)
	}
	if resultData.TholdKey != nil {
		t.Error("TholdKey should still be nil when not breached")
	}
}

func TestSimulateCheckQuoteBreached(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create a quote at $90,000 threshold
	originalEvent, err := sim.SimulateCreateQuote("test-domain", 90000.0)
	if err != nil {
		t.Fatalf("Failed to create quote: %v", err)
	}

	var originalData shared.PriceEvent
	json.Unmarshal([]byte(originalEvent.Content), &originalData)

	// Now price drops below threshold
	sim.PriceClient.Price = 85000 // Below $90,000 threshold
	sim.PriceClient.Stamp = 1700001000

	// Check quote - should be breached
	breachEvent, err := sim.SimulateCheckQuote("test-domain", originalData.TholdHash)
	if err != nil {
		t.Fatalf("Failed to check quote: %v", err)
	}

	// Should be a new breach event
	if breachEvent.ID == originalEvent.ID {
		t.Error("Should return new breach event when breached")
	}

	var breachData shared.PriceEvent
	json.Unmarshal([]byte(breachEvent.Content), &breachData)

	// Verify breach event structure
	if breachData.EventType != shared.EventTypeBreach {
		t.Errorf("EventType = %q, want %q", breachData.EventType, shared.EventTypeBreach)
	}
	if breachData.TholdKey == nil {
		t.Error("TholdKey should be revealed for breach event")
	}
	if breachData.IsExpired != true {
		t.Error("IsExpired should be true for breach event")
	}
	if breachData.EventPrice == nil || *breachData.EventPrice != 85000.0 {
		t.Error("EventPrice should be set to breach price")
	}

	// Verify secret matches commitment
	if err := crypto.VerifyThresholdCommitment(*breachData.TholdKey, breachData.TholdHash); err != nil {
		t.Errorf("Threshold commitment verification failed: %v", err)
	}

	// Verify Nostr signature on breach event
	if err := verifyNostrEvent(breachEvent); err != nil {
		t.Errorf("Nostr event verification failed: %v", err)
	}

	// Verify breach event was published (should have 2 events now)
	if len(sim.RelayClient.PublishedEvents) != 2 {
		t.Errorf("Expected 2 published events (create + breach), got %d", len(sim.RelayClient.PublishedEvents))
	}
}

func TestCheckQuoteNotFound(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Try to check non-existent quote
	_, err := sim.SimulateCheckQuote("test-domain", strings.Repeat("a", 40))
	if err == nil {
		t.Error("Expected error for non-existent quote")
	}
	if !strings.Contains(err.Error(), "fetch original event") {
		t.Errorf("Error should mention fetch failure: %v", err)
	}
}

// =============================================================================
// EvaluateQuotes Handler Tests
// =============================================================================

func TestSimulateEvaluateQuotesBatch(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create multiple quotes at different thresholds
	thresholds := []float64{90000.0, 95000.0, 85000.0, 80000.0}
	var tholdHashes []string

	for _, thold := range thresholds {
		event, err := sim.SimulateCreateQuote("test-domain", thold)
		if err != nil {
			t.Fatalf("Failed to create quote at %.0f: %v", thold, err)
		}
		var data shared.PriceEvent
		json.Unmarshal([]byte(event.Content), &data)
		tholdHashes = append(tholdHashes, data.TholdHash)
	}

	// Now evaluate all quotes with price at $88,000
	// - $90,000: breached (price < threshold)
	// - $95,000: breached (price < threshold)
	// - $85,000: active (price > threshold)
	// - $80,000: active (price > threshold)
	sim.PriceClient.Price = 88000
	sim.PriceClient.Stamp = 1700001000

	response, err := sim.SimulateEvaluateQuotes(tholdHashes)
	if err != nil {
		t.Fatalf("Failed to evaluate quotes: %v", err)
	}

	if len(response.Results) != 4 {
		t.Errorf("Expected 4 results, got %d", len(response.Results))
	}

	if response.CurrentPrice != 88000 {
		t.Errorf("CurrentPrice = %f, want 88000", response.CurrentPrice)
	}

	// Check individual results
	breachedCount := 0
	activeCount := 0
	for _, result := range response.Results {
		if result.Status == "breached" {
			breachedCount++
			if result.TholdKey == nil {
				t.Errorf("TholdKey should be revealed for breached quote %s", result.TholdHash)
			}
		} else if result.Status == "active" {
			activeCount++
			if result.TholdKey != nil {
				t.Errorf("TholdKey should be nil for active quote %s", result.TholdHash)
			}
		}
	}

	if breachedCount != 2 {
		t.Errorf("Expected 2 breached quotes, got %d", breachedCount)
	}
	if activeCount != 2 {
		t.Errorf("Expected 2 active quotes, got %d", activeCount)
	}
}

func TestSimulateEvaluateQuotesWithError(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create one valid quote
	event, _ := sim.SimulateCreateQuote("test-domain", 90000.0)
	var data shared.PriceEvent
	json.Unmarshal([]byte(event.Content), &data)

	// Mix valid and invalid thold_hashes
	tholdHashes := []string{
		data.TholdHash,
		strings.Repeat("b", 40), // Non-existent
	}

	response, err := sim.SimulateEvaluateQuotes(tholdHashes)
	if err != nil {
		t.Fatalf("Batch evaluate should not fail for partial errors: %v", err)
	}

	if len(response.Results) != 2 {
		t.Errorf("Expected 2 results, got %d", len(response.Results))
	}

	// First should be active or breached
	if response.Results[0].Status == "error" {
		t.Error("First result should not be error")
	}

	// Second should be error
	if response.Results[1].Status != "error" {
		t.Errorf("Second result should be error, got %s", response.Results[1].Status)
	}
	if response.Results[1].Error == nil {
		t.Error("Error message should be set for failed evaluation")
	}
}

// =============================================================================
// GenerateQuotes Handler Tests
// =============================================================================

func TestSimulateGenerateQuotes(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     1.50,
		StepSize:    0.05,
		Domain:      "test-gen",
		QuoteDomain: "auto-gen",
	}

	response, err := sim.SimulateGenerateQuotes(req)
	if err != nil {
		t.Fatalf("Failed to generate quotes: %v", err)
	}

	// Expected quotes: 1.35, 1.40, 1.45, 1.50 = 4 quotes (may be 3-4 due to floating point)
	if response.QuotesCreated < 3 || response.QuotesCreated > 4 {
		t.Errorf("Expected 3-4 quotes created, got %d", response.QuotesCreated)
	}

	if len(response.TholdHashes) != response.QuotesCreated {
		t.Errorf("TholdHashes count (%d) should match QuotesCreated (%d)", len(response.TholdHashes), response.QuotesCreated)
	}

	if response.CurrentPrice != 100000 {
		t.Errorf("CurrentPrice = %f, want 100000", response.CurrentPrice)
	}

	// Verify min/max thresholds
	expectedMinThold := 100000 * 1.35
	if response.Range.MinThold < expectedMinThold*0.99 || response.Range.MinThold > expectedMinThold*1.01 {
		t.Errorf("MinThold = %f, expected ~%f", response.Range.MinThold, expectedMinThold)
	}

	// Verify all hashes are valid and unique
	hashSet := make(map[string]bool)
	for _, hash := range response.TholdHashes {
		if !shared.IsValidTholdHash(hash) {
			t.Errorf("Invalid TholdHash: %s", hash)
		}
		if hashSet[hash] {
			t.Errorf("Duplicate TholdHash: %s", hash)
		}
		hashSet[hash] = true
	}

	// Verify all quotes are stored in relay
	if len(sim.RelayClient.PublishedEvents) != response.QuotesCreated {
		t.Errorf("Published events (%d) should match quotes created (%d)", len(sim.RelayClient.PublishedEvents), response.QuotesCreated)
	}
}

func TestSimulateGenerateQuotesLargeRange(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     5.0,
		StepSize:    0.05,
		Domain:      "test-gen",
		QuoteDomain: "auto-gen",
	}

	response, err := sim.SimulateGenerateQuotes(req)
	if err != nil {
		t.Fatalf("Failed to generate quotes: %v", err)
	}

	// (5.0 - 1.35) / 0.05 + 1 = 73 quotes (approximately)
	if response.QuotesCreated < 70 || response.QuotesCreated > 76 {
		t.Errorf("Expected ~73 quotes created, got %d", response.QuotesCreated)
	}

	t.Logf("Generated %d quotes from %.2f to %.2f", response.QuotesCreated, response.Range.MinThold, response.Range.MaxThold)
}

// =============================================================================
// Concurrent Handler Tests
// =============================================================================

func TestConcurrentCreateQuotes(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	numQuotes := 20
	var wg sync.WaitGroup
	events := make([]*shared.NostrEvent, numQuotes)
	errors := make([]error, numQuotes)

	for i := 0; i < numQuotes; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tholdPrice := 90000.0 - float64(idx*100)
			events[idx], errors[idx] = sim.SimulateCreateQuote(fmt.Sprintf("domain-%d", idx), tholdPrice)
		}(i)
	}

	wg.Wait()

	// Count successes
	successCount := 0
	for i := 0; i < numQuotes; i++ {
		if errors[i] == nil {
			successCount++
		}
	}

	if successCount < numQuotes {
		t.Errorf("Expected all %d quotes to succeed, got %d", numQuotes, successCount)
	}

	// Verify all events have unique IDs
	idSet := make(map[string]bool)
	for _, event := range events {
		if event != nil {
			if idSet[event.ID] {
				t.Error("Found duplicate event ID")
			}
			idSet[event.ID] = true
		}
	}
}

func TestConcurrentCheckQuotes(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Create quotes first
	var tholdHashes []string
	for i := 0; i < 10; i++ {
		event, _ := sim.SimulateCreateQuote(fmt.Sprintf("domain-%d", i), 90000.0-float64(i*1000))
		var data shared.PriceEvent
		json.Unmarshal([]byte(event.Content), &data)
		tholdHashes = append(tholdHashes, data.TholdHash)
	}

	// Drop price to trigger some breaches
	sim.PriceClient.Price = 87000
	sim.PriceClient.Stamp = 1700001000

	// Check all concurrently
	var wg sync.WaitGroup
	results := make([]*shared.NostrEvent, len(tholdHashes))
	errors := make([]error, len(tholdHashes))

	for i, hash := range tholdHashes {
		wg.Add(1)
		go func(idx int, h string) {
			defer wg.Done()
			results[idx], errors[idx] = sim.SimulateCheckQuote("test-domain", h)
		}(i, hash)
	}

	wg.Wait()

	// Count results
	breachedCount := 0
	activeCount := 0
	for i, event := range results {
		if errors[i] != nil {
			continue
		}
		var data shared.PriceEvent
		json.Unmarshal([]byte(event.Content), &data)
		if data.EventType == shared.EventTypeBreach {
			breachedCount++
		} else {
			activeCount++
		}
	}

	t.Logf("Concurrent check: %d breached, %d active", breachedCount, activeCount)
}

// =============================================================================
// Mock Client Tests
// =============================================================================

func TestMockRelayClientStoreAndFetch(t *testing.T) {
	relay := NewMockRelayClient()

	event := &shared.NostrEvent{
		ID:        "test-id",
		PubKey:    strings.Repeat("a", 64),
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", "test-dtag"}},
		Content:   "test content",
		Sig:       strings.Repeat("b", 128),
	}

	// Publish
	resp, err := relay.PublishEvent(event)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if !resp.Success {
		t.Error("Publish should succeed")
	}

	// Fetch by d-tag
	fetched, err := relay.FetchByDTag("test-dtag")
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if fetched.ID != event.ID {
		t.Errorf("Fetched ID = %s, want %s", fetched.ID, event.ID)
	}

	// Fetch non-existent
	_, err = relay.FetchByDTag("non-existent")
	if err == nil {
		t.Error("Expected error for non-existent d-tag")
	}
}

func TestMockPriceClient(t *testing.T) {
	client := NewMockPriceClient(100000, 1700000000)

	data, err := client.FetchPrice()
	if err != nil {
		t.Fatalf("FetchPrice failed: %v", err)
	}
	if data.Price != 100000 {
		t.Errorf("Price = %f, want 100000", data.Price)
	}
	if data.Stamp != 1700000000 {
		t.Errorf("Stamp = %d, want 1700000000", data.Stamp)
	}
	if data.Origin != "mock-chainlink" {
		t.Errorf("Origin = %q, want %q", data.Origin, "mock-chainlink")
	}

	// Test with error
	client.Error = fmt.Errorf("network failure")
	_, err = client.FetchPrice()
	if err == nil {
		t.Error("Expected error")
	}
}

// =============================================================================
// Nostr Event Tests
// =============================================================================

func TestNostrEventSignAndVerify(t *testing.T) {
	kd, err := crypto.DeriveKeys(testPrivateKey)
	if err != nil {
		t.Fatalf("Key derivation failed: %v", err)
	}

	event := &shared.NostrEvent{
		PubKey:    kd.SchnorrPubkey,
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", "test-tag"}},
		Content:   "test content",
	}

	// Sign
	if err := signNostrEvent(event, kd.PrivateKey); err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	if event.ID == "" {
		t.Error("ID should be set")
	}
	if event.Sig == "" {
		t.Error("Sig should be set")
	}
	if len(event.ID) != 64 {
		t.Errorf("ID length = %d, want 64", len(event.ID))
	}
	if len(event.Sig) != 128 {
		t.Errorf("Sig length = %d, want 128", len(event.Sig))
	}

	// Verify
	if err := verifyNostrEvent(event); err != nil {
		t.Errorf("Verify failed: %v", err)
	}

	// Tamper with content
	event.Content = "tampered"
	if err := verifyNostrEvent(event); err == nil {
		t.Error("Should fail for tampered event")
	}
}

func TestNostrEventSerialize(t *testing.T) {
	event := &shared.NostrEvent{
		PubKey:    strings.Repeat("a", 64),
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", "test"}, {"p", "pubkey"}},
		Content:   "hello world",
	}

	serialized := serializeNostrEvent(event)

	// Should contain expected fields
	if !strings.Contains(serialized, "[0,") {
		t.Error("Should start with [0,")
	}
	if !strings.Contains(serialized, "30078") {
		t.Error("Should contain kind")
	}
	if !strings.Contains(serialized, "1700000000") {
		t.Error("Should contain created_at")
	}
	if !strings.Contains(serialized, "hello world") {
		t.Error("Should contain content")
	}
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkSimulateCreateQuote(b *testing.B) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sim.SimulateCreateQuote("test-domain", 90000.0)
	}
}

func BenchmarkSimulateGenerateQuotes(b *testing.B) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	req := &shared.GenerateQuotesRequest{
		RateMin:  1.35,
		RateMax:  1.50,
		StepSize: 0.05,
		Domain:   "bench",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sim.SimulateGenerateQuotes(req)
	}
}

// =============================================================================
// High Volume Tests (300+ contracts)
// =============================================================================

func TestGenerate300PlusContracts(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// Generate 300+ contracts: 1.01 to 4.01 with 0.01 step = 301 contracts
	req := &shared.GenerateQuotesRequest{
		RateMin:     1.01,
		RateMax:     4.01,
		StepSize:    0.01,
		Domain:      "high-volume",
		QuoteDomain: "hv",
	}

	response, err := sim.SimulateGenerateQuotes(req)
	if err != nil {
		t.Fatalf("Failed to generate quotes: %v", err)
	}

	if response.QuotesCreated < 300 {
		t.Errorf("Expected 300+ quotes, got %d", response.QuotesCreated)
	}

	t.Logf("Successfully generated %d contracts", response.QuotesCreated)
	t.Logf("Price range: $%.2f to $%.2f", response.Range.MinThold, response.Range.MaxThold)
	t.Logf("Published events: %d", len(sim.RelayClient.PublishedEvents))

	// Verify all hashes are unique
	hashSet := make(map[string]bool)
	for _, hash := range response.TholdHashes {
		if hashSet[hash] {
			t.Errorf("Duplicate TholdHash found: %s", hash)
		}
		hashSet[hash] = true
	}

	// Verify all events are valid
	for i, event := range sim.RelayClient.PublishedEvents {
		if err := verifyNostrEvent(event); err != nil {
			t.Errorf("Event %d verification failed: %v", i, err)
		}
	}

	// Verify all are stored in relay by d-tag
	for _, hash := range response.TholdHashes {
		_, err := sim.RelayClient.FetchByDTag(hash)
		if err != nil {
			t.Errorf("Failed to fetch event by d-tag %s: %v", hash[:8], err)
		}
	}
}

func TestEvaluate300PlusContracts(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	// First generate 300+ contracts
	genReq := &shared.GenerateQuotesRequest{
		RateMin:     1.01,
		RateMax:     4.01,
		StepSize:    0.01,
		Domain:      "eval-volume",
		QuoteDomain: "ev",
	}

	genResponse, err := sim.SimulateGenerateQuotes(genReq)
	if err != nil {
		t.Fatalf("Failed to generate quotes: %v", err)
	}

	if genResponse.QuotesCreated < 300 {
		t.Fatalf("Expected 300+ quotes, got %d", genResponse.QuotesCreated)
	}

	t.Logf("Generated %d contracts for evaluation", genResponse.QuotesCreated)

	// Now drop price to $150,000 (should breach contracts with thresholds > $150k)
	// Thresholds range from $101,000 (1.01x) to $401,000 (4.01x)
	// At $150k: thresholds > $150k are NOT breached, thresholds <= $150k ARE breached
	sim.PriceClient.Price = 150000
	sim.PriceClient.Stamp = 1700001000

	// Evaluate all contracts
	evalResponse, err := sim.SimulateEvaluateQuotes(genResponse.TholdHashes)
	if err != nil {
		t.Fatalf("Failed to evaluate quotes: %v", err)
	}

	if len(evalResponse.Results) != len(genResponse.TholdHashes) {
		t.Errorf("Expected %d results, got %d", len(genResponse.TholdHashes), len(evalResponse.Results))
	}

	// Count results
	breachedCount := 0
	activeCount := 0
	errorCount := 0
	for _, result := range evalResponse.Results {
		switch result.Status {
		case "breached":
			breachedCount++
			if result.TholdKey == nil {
				t.Error("Breached quote should have TholdKey revealed")
			}
		case "active":
			activeCount++
		case "error":
			errorCount++
		}
	}

	t.Logf("Evaluation results: %d breached, %d active, %d errors", breachedCount, activeCount, errorCount)

	// With price at $150k:
	// - Thresholds from $101k to $150k (rates 1.01-1.50) should be ACTIVE (price >= threshold)
	// - Thresholds from $150k+ to $401k (rates 1.50+-4.01) should be BREACHED (price < threshold)
	// Approximately: ~50 active, ~250 breached
	if breachedCount < 200 {
		t.Errorf("Expected 200+ breached quotes, got %d", breachedCount)
	}
	if activeCount < 40 {
		t.Errorf("Expected 40+ active quotes, got %d", activeCount)
	}
	if errorCount > 0 {
		t.Errorf("Expected 0 errors, got %d", errorCount)
	}

	// Verify breach events were published
	// Original contracts + breach events
	totalPublished := len(sim.RelayClient.PublishedEvents)
	expectedMin := genResponse.QuotesCreated + breachedCount
	if totalPublished < expectedMin {
		t.Errorf("Expected at least %d published events, got %d", expectedMin, totalPublished)
	}

	t.Logf("Total published events: %d (original: %d, breach updates: %d)", totalPublished, genResponse.QuotesCreated, breachedCount)
}

func TestCreate300ContractsIndividually(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	numContracts := 300
	var tholdHashes []string
	var events []*shared.NostrEvent

	for i := 0; i < numContracts; i++ {
		// Vary threshold prices from 50% to 200% of current price
		rate := 0.5 + (float64(i) / float64(numContracts) * 1.5)
		tholdPrice := 100000 * rate

		// Skip prices too close to current (within 1%)
		if tholdPrice > 99000 && tholdPrice < 101000 {
			continue
		}

		event, err := sim.SimulateCreateQuote(fmt.Sprintf("individual-%d", i), tholdPrice)
		if err != nil {
			t.Logf("Skipping contract %d at threshold %.0f: %v", i, tholdPrice, err)
			continue
		}

		var data shared.PriceEvent
		json.Unmarshal([]byte(event.Content), &data)
		tholdHashes = append(tholdHashes, data.TholdHash)
		events = append(events, event)
	}

	t.Logf("Created %d individual contracts", len(events))

	if len(events) < 290 {
		t.Errorf("Expected ~290+ contracts (some skipped due to threshold distance), got %d", len(events))
	}

	// Verify all hashes unique
	hashSet := make(map[string]bool)
	for _, hash := range tholdHashes {
		if hashSet[hash] {
			t.Error("Found duplicate hash")
		}
		hashSet[hash] = true
	}

	// Verify all events are valid Nostr events
	for i, event := range events {
		if err := verifyNostrEvent(event); err != nil {
			t.Errorf("Event %d verification failed: %v", i, err)
		}
	}
}

func BenchmarkNostrEventSign(b *testing.B) {
	kd, _ := crypto.DeriveKeys(testPrivateKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &shared.NostrEvent{
			PubKey:    kd.SchnorrPubkey,
			CreatedAt: 1700000000,
			Kind:      30078,
			Tags:      [][]string{{"d", "test"}},
			Content:   "benchmark content",
		}
		signNostrEvent(event, kd.PrivateKey)
	}
}

// BenchmarkGenerateQuotes_1_35_to_5_00 benchmarks generating quotes from 1.35x to 5.00x
// This simulates the CRE cron trigger for auto-generating price threshold quotes
func BenchmarkGenerateQuotes_1_35_to_5_00(b *testing.B) {
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		sim := NewWorkflowSimulator(testPrivateKey)
		sim.PriceClient.Price = 100000
		sim.PriceClient.Stamp = 1700000000

		req := &shared.GenerateQuotesRequest{
			RateMin:     1.35,
			RateMax:     5.00,
			StepSize:    0.05,
			Domain:      "benchmark",
			QuoteDomain: "bench",
		}

		sim.SimulateGenerateQuotes(req)
	}
}

// TestGenerateQuotes_1_35_to_5_00_Timing provides detailed timing breakdown
func TestGenerateQuotes_1_35_to_5_00_Timing(t *testing.T) {
	sim := NewWorkflowSimulator(testPrivateKey)
	sim.PriceClient.Price = 100000
	sim.PriceClient.Stamp = 1700000000

	req := &shared.GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     5.00,
		StepSize:    0.01, // 1% increments = 366 contracts
		Domain:      "timing-test",
		QuoteDomain: "tt",
	}

	// Calculate expected quotes
	expectedQuotes := int((req.RateMax-req.RateMin)/req.StepSize) + 1
	t.Logf("Expected quotes: %d (from %.2fx to %.2fx at %.2f step)", expectedQuotes, req.RateMin, req.RateMax, req.StepSize)

	// Run multiple iterations for average
	iterations := 10
	var totalDuration int64

	for i := 0; i < iterations; i++ {
		// Fresh simulator each time
		sim := NewWorkflowSimulator(testPrivateKey)
		sim.PriceClient.Price = 100000
		sim.PriceClient.Stamp = 1700000000

		start := time.Now()
		response, err := sim.SimulateGenerateQuotes(req)
		elapsed := time.Since(start)
		totalDuration += elapsed.Nanoseconds()

		if err != nil {
			t.Fatalf("Iteration %d failed: %v", i, err)
		}

		if i == 0 {
			t.Logf("Quotes created: %d", response.QuotesCreated)
			t.Logf("Price range: $%.2f to $%.2f", response.Range.MinThold, response.Range.MaxThold)
		}
	}

	avgDuration := time.Duration(totalDuration / int64(iterations))
	t.Logf("")
	t.Logf("=== TIMING RESULTS (average of %d runs) ===", iterations)
	t.Logf("Total time: %v", avgDuration)
	t.Logf("Per contract: %v", avgDuration/time.Duration(expectedQuotes))
	t.Logf("Contracts/second: %.0f", float64(expectedQuotes)/avgDuration.Seconds())

	// Estimate CRE overhead
	t.Logf("")
	t.Logf("=== CRE PRODUCTION ESTIMATES ===")
	t.Logf("Local crypto time: %v", avgDuration)

	// CRE adds: network latency for price fetch, DON consensus, relay publish per contract
	// Estimate: ~100ms price fetch + ~50ms per relay publish (with consensus)
	estimatedPriceFetch := 100 * time.Millisecond
	estimatedRelayPublishPer := 50 * time.Millisecond
	estimatedCRETotal := avgDuration + estimatedPriceFetch + (time.Duration(expectedQuotes) * estimatedRelayPublishPer)

	t.Logf("Estimated price fetch (1x): ~%v", estimatedPriceFetch)
	t.Logf("Estimated relay publish per contract: ~%v", estimatedRelayPublishPer)
	t.Logf("Estimated CRE sequential total: ~%v", estimatedCRETotal)

	// With parallel relay publishing (CRE promise-based)
	// All publishes happen in parallel, so ~1 round trip
	estimatedParallelPublish := 200 * time.Millisecond // One batch with consensus
	estimatedCREParallel := avgDuration + estimatedPriceFetch + estimatedParallelPublish
	t.Logf("Estimated CRE parallel total: ~%v", estimatedCREParallel)
}

// BenchmarkContractCreationOnly benchmarks just the crypto operations (no relay)
func BenchmarkContractCreationOnly(b *testing.B) {
	b.ReportAllocs()

	kd, _ := crypto.DeriveKeys(testPrivateKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Just the contract creation (no relay publish)
		crypto.CreatePriceContract(
			testPrivateKey,
			crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    1700000000,
			},
			uint32(135000+i),
		)
	}
}

// BenchmarkFullContractWithSigning benchmarks contract + Nostr event signing
func BenchmarkFullContractWithSigning(b *testing.B) {
	b.ReportAllocs()

	kd, _ := crypto.DeriveKeys(testPrivateKey)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Create contract
		contract, _ := crypto.CreatePriceContract(
			testPrivateKey,
			crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    1700000000,
			},
			uint32(135000+i),
		)

		// Sign oracle signature
		crypto.SignSchnorr(kd.PrivateKey, contract.ContractID)

		// Create and sign Nostr event
		event := &shared.NostrEvent{
			PubKey:    kd.SchnorrPubkey,
			CreatedAt: 1700000000,
			Kind:      30078,
			Tags:      [][]string{{"d", contract.TholdHash}},
			Content:   "benchmark",
		}
		signNostrEvent(event, kd.PrivateKey)
	}
}
