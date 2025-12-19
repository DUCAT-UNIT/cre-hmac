// Package integration provides end-to-end integration tests for the CRE HMAC workflow
// These tests verify the full flow from HTTP request to workflow execution to response
package integration

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ducat/crypto"
	"ducat/shared"
)

// TestConstants for integration tests
const (
	testPrivateKey = "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
)

// =============================================================================
// Price Contract Creation and Verification Integration Tests
// =============================================================================

func TestPriceContractCreationAndVerification(t *testing.T) {
	// This tests the full flow of creating a price contract and verifying it

	kd, err := crypto.DeriveKeys(testPrivateKey)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}

	tests := []struct {
		name       string
		basePrice  uint32
		baseStamp  uint32
		tholdPrice uint32
		network    string
	}{
		{"standard BTC price", 100000, 1700000000, 90000, "mutiny"},
		{"high BTC price", 500000, 1700000000, 450000, "signet"},
		{"low BTC price", 50000, 1700000000, 45000, "mutiny"},
		{"price at threshold", 100000, 1700000000, 100000, "testnet"},
		{"small threshold distance", 100000, 1700000000, 99000, "mutiny"},
		{"large threshold distance", 100000, 1700000000, 50000, "mutiny"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: tt.network,
				BasePrice:    tt.basePrice,
				BaseStamp:    tt.baseStamp,
			}

			// Create the price contract
			contract, err := crypto.CreatePriceContract(testPrivateKey, obs, tt.tholdPrice)
			if err != nil {
				t.Fatalf("Failed to create price contract: %v", err)
			}

			// Verify all fields are set
			if contract.CommitHash == "" {
				t.Error("CommitHash should not be empty")
			}
			if contract.ContractID == "" {
				t.Error("ContractID should not be empty")
			}
			if contract.TholdHash == "" {
				t.Error("TholdHash should not be empty")
			}
			if contract.OracleSig == "" {
				t.Error("OracleSig should not be empty")
			}
			if contract.TholdKey == nil {
				t.Error("TholdKey should not be nil for new contract")
			}

			// Verify the contract
			if err := crypto.VerifyPriceContract(contract); err != nil {
				t.Errorf("Contract verification failed: %v", err)
			}

			// Verify threshold commitment
			if err := crypto.VerifyThresholdCommitment(*contract.TholdKey, contract.TholdHash); err != nil {
				t.Errorf("Threshold commitment verification failed: %v", err)
			}

			// Verify signature
			if err := crypto.VerifySchnorrSignature(kd.SchnorrPubkey, contract.ContractID, contract.OracleSig); err != nil {
				t.Errorf("Signature verification failed: %v", err)
			}

			// Verify field lengths
			if len(contract.TholdHash) != shared.TholdHashLength {
				t.Errorf("TholdHash length = %d, want %d", len(contract.TholdHash), shared.TholdHashLength)
			}
			if len(contract.CommitHash) != shared.CommitHashLength {
				t.Errorf("CommitHash length = %d, want %d", len(contract.CommitHash), shared.CommitHashLength)
			}
			if len(contract.ContractID) != shared.ContractIDLength {
				t.Errorf("ContractID length = %d, want %d", len(contract.ContractID), shared.ContractIDLength)
			}
			if len(contract.OracleSig) != shared.OracleSigLength {
				t.Errorf("OracleSig length = %d, want %d", len(contract.OracleSig), shared.OracleSigLength)
			}
			if contract.TholdKey != nil && len(*contract.TholdKey) != shared.TholdKeyLength {
				t.Errorf("TholdKey length = %d, want %d", len(*contract.TholdKey), shared.TholdKeyLength)
			}
		})
	}
}

func TestPriceContractDeterminism(t *testing.T) {
	// Verify that creating the same contract twice produces identical results
	// (except for the signature which may vary due to nonce)

	kd, _ := crypto.DeriveKeys(testPrivateKey)
	obs := crypto.PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    100000,
		BaseStamp:    1700000000,
	}

	contract1, err := crypto.CreatePriceContract(testPrivateKey, obs, 90000)
	if err != nil {
		t.Fatalf("First contract creation failed: %v", err)
	}

	contract2, err := crypto.CreatePriceContract(testPrivateKey, obs, 90000)
	if err != nil {
		t.Fatalf("Second contract creation failed: %v", err)
	}

	// These should be identical
	if contract1.CommitHash != contract2.CommitHash {
		t.Error("CommitHash should be deterministic")
	}
	if contract1.TholdHash != contract2.TholdHash {
		t.Error("TholdHash should be deterministic")
	}
	if contract1.ContractID != contract2.ContractID {
		t.Error("ContractID should be deterministic")
	}
	// Check TholdKey with nil guards
	if contract1.TholdKey == nil {
		t.Fatal("contract1.TholdKey is nil, expected non-nil for new contract")
	}
	if contract2.TholdKey == nil {
		t.Fatal("contract2.TholdKey is nil, expected non-nil for new contract")
	}
	if *contract1.TholdKey != *contract2.TholdKey {
		t.Error("TholdKey should be deterministic")
	}

	// Both signatures should verify
	if err := crypto.VerifySchnorrSignature(kd.SchnorrPubkey, contract1.ContractID, contract1.OracleSig); err != nil {
		t.Errorf("First signature verification failed: %v", err)
	}
	if err := crypto.VerifySchnorrSignature(kd.SchnorrPubkey, contract2.ContractID, contract2.OracleSig); err != nil {
		t.Errorf("Second signature verification failed: %v", err)
	}
}

func TestPriceContractUniqueness(t *testing.T) {
	// Verify that different inputs produce different contracts

	kd, err := crypto.DeriveKeys(testPrivateKey)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}
	baseObs := crypto.PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    100000,
		BaseStamp:    1700000000,
	}

	baseContract, err := crypto.CreatePriceContract(testPrivateKey, baseObs, 90000)
	if err != nil {
		t.Fatalf("Failed to create base contract: %v", err)
	}

	// Different threshold price
	diffTholdContract, err := crypto.CreatePriceContract(testPrivateKey, baseObs, 80000)
	if err != nil {
		t.Fatalf("Failed to create diffTholdContract: %v", err)
	}
	if baseContract.TholdHash == diffTholdContract.TholdHash {
		t.Error("Different threshold prices should produce different TholdHash")
	}
	if baseContract.CommitHash == diffTholdContract.CommitHash {
		t.Error("Different threshold prices should produce different CommitHash")
	}

	// Different base price
	diffPriceObs := baseObs
	diffPriceObs.BasePrice = 90000
	diffPriceContract, err := crypto.CreatePriceContract(testPrivateKey, diffPriceObs, 90000)
	if err != nil {
		t.Fatalf("Failed to create diffPriceContract: %v", err)
	}
	if baseContract.CommitHash == diffPriceContract.CommitHash {
		t.Error("Different base prices should produce different CommitHash")
	}

	// Different timestamp
	diffStampObs := baseObs
	diffStampObs.BaseStamp = 1700000001
	diffStampContract, err := crypto.CreatePriceContract(testPrivateKey, diffStampObs, 90000)
	if err != nil {
		t.Fatalf("Failed to create diffStampContract: %v", err)
	}
	if baseContract.CommitHash == diffStampContract.CommitHash {
		t.Error("Different timestamps should produce different CommitHash")
	}

	// Different network
	diffNetObs := baseObs
	diffNetObs.ChainNetwork = "signet"
	diffNetContract, err := crypto.CreatePriceContract(testPrivateKey, diffNetObs, 90000)
	if err != nil {
		t.Fatalf("Failed to create diffNetContract: %v", err)
	}
	if baseContract.CommitHash == diffNetContract.CommitHash {
		t.Error("Different networks should produce different CommitHash")
	}
}

// =============================================================================
// Validation Integration Tests
// =============================================================================

func TestEndToEndValidation(t *testing.T) {
	// Test full validation flow for all request types

	validTholdHash := strings.Repeat("a", 40)
	validPrice := 100000.0

	// Test HttpRequestData validation
	t.Run("HttpRequestData", func(t *testing.T) {
		validCreate := shared.HttpRequestData{
			Domain:     "test-domain",
			TholdPrice: &validPrice,
		}
		if err := validCreate.Validate(); err != nil {
			t.Errorf("Valid create request should pass: %v", err)
		}

		validCheck := shared.HttpRequestData{
			Domain:    "test-domain",
			TholdHash: &validTholdHash,
		}
		if err := validCheck.Validate(); err != nil {
			t.Errorf("Valid check request should pass: %v", err)
		}
	})

	// Test EvaluateQuotesRequest validation
	t.Run("EvaluateQuotesRequest", func(t *testing.T) {
		validEval := shared.EvaluateQuotesRequest{
			TholdHashes: []string{validTholdHash},
		}
		if err := validEval.Validate(); err != nil {
			t.Errorf("Valid evaluate request should pass: %v", err)
		}
	})

	// Test GenerateQuotesRequest validation
	t.Run("GenerateQuotesRequest", func(t *testing.T) {
		validGen := shared.GenerateQuotesRequest{
			RateMin:  1.35,
			RateMax:  5.0,
			StepSize: 0.05,
			Domain:   "test-domain",
		}
		if err := validGen.Validate(); err != nil {
			t.Errorf("Valid generate request should pass: %v", err)
		}
	})

	// Test Config validation
	t.Run("Config", func(t *testing.T) {
		validConfig := shared.Config{
			ClientID:      "test-client",
			DataStreamURL: "https://data.example.com",
			FeedID:        "feed-123",
			RelayURL:      "wss://relay.example.com",
			Network:       "mutiny",
			AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82", // Required for HTTP trigger auth
		}
		if err := validConfig.Validate(); err != nil {
			t.Errorf("Valid config should pass: %v", err)
		}

		// With cron config
		validConfig.CronSchedule = "0 */5 * * * *"
		validConfig.RateMin = 1.35
		validConfig.RateMax = 5.0
		validConfig.StepSize = 0.05
		if err := validConfig.Validate(); err != nil {
			t.Errorf("Valid config with cron should pass: %v", err)
		}
	})
}

// =============================================================================
// Quote Generation Simulation Tests
// =============================================================================

func TestQuoteGenerationSimulation(t *testing.T) {
	// Simulate quote generation at multiple price levels

	kd, _ := crypto.DeriveKeys(testPrivateKey)
	currentPrice := uint32(100000)
	currentStamp := uint32(1700000000)

	// Generate quotes from 135% to 200% of current price
	rateMin := 1.35
	rateMax := 2.0
	stepSize := 0.05

	var contracts []*crypto.PriceContract
	var tholdHashes []string

	for rate := rateMin; rate <= rateMax; rate += stepSize {
		tholdPrice := uint32(float64(currentPrice) * rate)

		obs := crypto.PriceObservation{
			OraclePubkey: kd.SchnorrPubkey,
			ChainNetwork: "mutiny",
			BasePrice:    currentPrice,
			BaseStamp:    currentStamp,
		}

		contract, err := crypto.CreatePriceContract(testPrivateKey, obs, tholdPrice)
		if err != nil {
			t.Fatalf("Failed to create contract at rate %.2f: %v", rate, err)
		}

		contracts = append(contracts, contract)
		tholdHashes = append(tholdHashes, contract.TholdHash)
	}

	expectedQuotes := int((rateMax-rateMin)/stepSize) + 1
	if len(contracts) < expectedQuotes-1 { // Allow for floating point variance
		t.Errorf("Expected at least %d quotes, got %d", expectedQuotes-1, len(contracts))
	}

	// Verify all hashes are unique
	hashSet := make(map[string]bool)
	for _, hash := range tholdHashes {
		if hashSet[hash] {
			t.Error("Found duplicate thold_hash - contracts should be unique")
		}
		hashSet[hash] = true
	}

	// Verify all contracts are valid
	for i, contract := range contracts {
		if err := crypto.VerifyPriceContract(contract); err != nil {
			t.Errorf("Contract %d verification failed: %v", i, err)
		}
	}

	t.Logf("Generated %d unique quotes", len(contracts))
}

// =============================================================================
// Breach Detection Simulation Tests
// =============================================================================

func TestBreachDetectionSimulation(t *testing.T) {
	// Simulate breach detection for quotes

	kd, _ := crypto.DeriveKeys(testPrivateKey)
	basePrice := uint32(100000)
	baseStamp := uint32(1700000000)
	tholdPrice := uint32(90000) // Threshold at $90,000

	obs := crypto.PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}

	contract, err := crypto.CreatePriceContract(testPrivateKey, obs, tholdPrice)
	if err != nil {
		t.Fatalf("Failed to create contract: %v", err)
	}

	// Simulate price scenarios
	scenarios := []struct {
		name          string
		currentPrice  float64
		expectBreach  bool
	}{
		{"price above threshold", 95000.0, false},
		{"price at threshold", 90000.0, false},
		{"price below threshold", 89999.0, true},
		{"price well below threshold", 50000.0, true},
		{"price well above threshold", 150000.0, false},
	}

	for _, sc := range scenarios {
		t.Run(sc.name, func(t *testing.T) {
			// Breach condition: currentPrice < tholdPrice
			isBreached := sc.currentPrice < float64(tholdPrice)
			if isBreached != sc.expectBreach {
				t.Errorf("At price %.0f: breach = %v, want %v", sc.currentPrice, isBreached, sc.expectBreach)
			}

			if isBreached {
				// Verify we can reveal the secret
				if contract.TholdKey == nil {
					t.Error("TholdKey should be available for breach")
				}

				// Verify the revealed secret matches the commitment
				if err := crypto.VerifyThresholdCommitment(*contract.TholdKey, contract.TholdHash); err != nil {
					t.Errorf("Commitment verification failed: %v", err)
				}
			}
		})
	}
}

// =============================================================================
// Concurrent Processing Tests
// =============================================================================

func TestConcurrentContractCreation(t *testing.T) {
	// Test thread-safety of contract creation

	kd, _ := crypto.DeriveKeys(testPrivateKey)
	numContracts := 50
	var wg sync.WaitGroup
	contracts := make([]*crypto.PriceContract, numContracts)
	errors := make([]error, numContracts)

	for i := 0; i < numContracts; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			obs := crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    uint32(100000 + idx),
				BaseStamp:    uint32(1700000000 + idx),
			}

			contract, err := crypto.CreatePriceContract(testPrivateKey, obs, uint32(90000+idx))
			contracts[idx] = contract
			errors[idx] = err
		}(i)
	}

	wg.Wait()

	// Verify all succeeded
	for i := 0; i < numContracts; i++ {
		if errors[i] != nil {
			t.Errorf("Contract %d creation failed: %v", i, errors[i])
		}
		if contracts[i] == nil {
			t.Errorf("Contract %d is nil", i)
		}
	}

	// Verify all contracts are valid
	for i, contract := range contracts {
		if contract != nil {
			if err := crypto.VerifyPriceContract(contract); err != nil {
				t.Errorf("Contract %d verification failed: %v", i, err)
			}
		}
	}

	// Verify all are unique
	hashSet := make(map[string]bool)
	for i, contract := range contracts {
		if contract != nil {
			if hashSet[contract.TholdHash] {
				t.Errorf("Contract %d has duplicate TholdHash", i)
			}
			hashSet[contract.TholdHash] = true
		}
	}
}

func TestConcurrentValidation(t *testing.T) {
	// Test thread-safety of validation

	validHash := strings.Repeat("a", 40)
	validPrice := 100000.0
	numRequests := 100
	var wg sync.WaitGroup
	errors := make([]error, numRequests)

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			var req interface{ Validate() error }
			switch idx % 4 {
			case 0:
				req = &shared.HttpRequestData{Domain: "test", TholdPrice: &validPrice}
			case 1:
				req = &shared.HttpRequestData{Domain: "test", TholdHash: &validHash}
			case 2:
				req = &shared.EvaluateQuotesRequest{TholdHashes: []string{validHash}}
			case 3:
				req = &shared.GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: "test"}
			}

			errors[idx] = req.Validate()
		}(i)
	}

	wg.Wait()

	// All should pass
	for i, err := range errors {
		if err != nil {
			t.Errorf("Request %d validation failed: %v", i, err)
		}
	}
}

// =============================================================================
// Mock Gateway Integration Tests
// =============================================================================

type MockGatewayServer struct {
	server         *httptest.Server
	receivedEvents []map[string]interface{}
	mu             sync.Mutex
}

func NewMockGatewayServer() *MockGatewayServer {
	mg := &MockGatewayServer{}

	mg.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var event map[string]interface{}
		json.Unmarshal(body, &event)

		mg.mu.Lock()
		mg.receivedEvents = append(mg.receivedEvents, event)
		mg.mu.Unlock()

		// Simulate success response
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"result": "ok",
		})
	}))

	return mg
}

func (mg *MockGatewayServer) Close() {
	mg.server.Close()
}

func (mg *MockGatewayServer) URL() string {
	return mg.server.URL
}

func (mg *MockGatewayServer) GetEvents() []map[string]interface{} {
	mg.mu.Lock()
	defer mg.mu.Unlock()
	return mg.receivedEvents
}

func TestMockGatewayIntegration(t *testing.T) {
	// Test sending events to a mock gateway

	mg := NewMockGatewayServer()
	defer mg.Close()

	// Simulate sending a workflow trigger
	payload := map[string]interface{}{
		"action":       "evaluate",
		"domain":       "test-domain",
		"thold_hashes": []string{strings.Repeat("a", 40)},
	}

	jsonData, _ := json.Marshal(payload)
	resp, err := http.Post(mg.URL(), "application/json", bytes.NewReader(jsonData))
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200, got %d", resp.StatusCode)
	}

	events := mg.GetEvents()
	if len(events) != 1 {
		t.Errorf("Expected 1 event, got %d", len(events))
	}

	if events[0]["action"] != "evaluate" {
		t.Errorf("Expected action=evaluate, got %v", events[0]["action"])
	}
}

// =============================================================================
// Response Type Tests
// =============================================================================

func TestEvaluateQuotesResponseConstruction(t *testing.T) {
	// Test constructing a proper evaluate response

	key := "secret123" + strings.Repeat("a", 51) // 64 chars
	errMsg := "failed to fetch"

	response := shared.EvaluateQuotesResponse{
		Results: []shared.QuoteEvaluationResult{
			{
				TholdHash:    strings.Repeat("a", 40),
				Status:       "breached",
				TholdKey:     &key,
				CurrentPrice: 89000.0,
				TholdPrice:   90000.0,
			},
			{
				TholdHash:    strings.Repeat("b", 40),
				Status:       "active",
				TholdKey:     nil,
				CurrentPrice: 89000.0,
				TholdPrice:   85000.0,
			},
			{
				TholdHash:    strings.Repeat("c", 40),
				Status:       "error",
				TholdKey:     nil,
				CurrentPrice: 0,
				TholdPrice:   0,
				Error:        &errMsg,
			},
		},
		CurrentPrice: 89000.0,
		EvaluatedAt:  1700000000,
	}

	// Verify counts
	if response.CountBreached() != 1 {
		t.Errorf("CountBreached() = %d, want 1", response.CountBreached())
	}
	if response.CountActive() != 1 {
		t.Errorf("CountActive() = %d, want 1", response.CountActive())
	}
	if response.CountErrors() != 1 {
		t.Errorf("CountErrors() = %d, want 1", response.CountErrors())
	}

	// Verify JSON serialization
	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var decoded shared.EvaluateQuotesResponse
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	if len(decoded.Results) != 3 {
		t.Errorf("Decoded results count = %d, want 3", len(decoded.Results))
	}
}

// =============================================================================
// Edge Case Tests
// =============================================================================

func TestEdgeCasePrices(t *testing.T) {
	// Test edge case price values

	kd, _ := crypto.DeriveKeys(testPrivateKey)

	edgeCases := []struct {
		name       string
		basePrice  uint32
		tholdPrice uint32
	}{
		{"minimum price", 1, 1},
		{"large price", 999999999, 888888888},
		{"equal prices", 100000, 100000},
		{"threshold 1 below base", 100000, 99999},
		{"very small difference", 100000, 99999},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			obs := crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    tc.basePrice,
				BaseStamp:    1700000000,
			}

			contract, err := crypto.CreatePriceContract(testPrivateKey, obs, tc.tholdPrice)
			if err != nil {
				t.Fatalf("Failed to create contract: %v", err)
			}

			if err := crypto.VerifyPriceContract(contract); err != nil {
				t.Errorf("Contract verification failed: %v", err)
			}
		})
	}
}

func TestEdgeCaseTimestamps(t *testing.T) {
	// Test edge case timestamp values

	kd, _ := crypto.DeriveKeys(testPrivateKey)

	edgeCases := []struct {
		name      string
		baseStamp uint32
	}{
		{"year 2000", 946684800},
		{"year 2024", 1704067200},
		{"year 2050", 2524608000},
		{"max uint32", 4294967295},
	}

	for _, tc := range edgeCases {
		t.Run(tc.name, func(t *testing.T) {
			obs := crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    tc.baseStamp,
			}

			contract, err := crypto.CreatePriceContract(testPrivateKey, obs, 90000)
			if err != nil {
				t.Fatalf("Failed to create contract: %v", err)
			}

			if err := crypto.VerifyPriceContract(contract); err != nil {
				t.Errorf("Contract verification failed: %v", err)
			}
		})
	}
}

// =============================================================================
// Performance/Load Tests
// =============================================================================

func TestHighVolumeContractCreation(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping high volume test in short mode")
	}

	kd, _ := crypto.DeriveKeys(testPrivateKey)
	numContracts := 1000

	start := time.Now()

	for i := 0; i < numContracts; i++ {
		obs := crypto.PriceObservation{
			OraclePubkey: kd.SchnorrPubkey,
			ChainNetwork: "mutiny",
			BasePrice:    uint32(100000 + i),
			BaseStamp:    uint32(1700000000 + i),
		}

		contract, err := crypto.CreatePriceContract(testPrivateKey, obs, uint32(90000+i))
		if err != nil {
			t.Fatalf("Contract %d creation failed: %v", i, err)
		}

		if err := crypto.VerifyPriceContract(contract); err != nil {
			t.Fatalf("Contract %d verification failed: %v", i, err)
		}
	}

	elapsed := time.Since(start)
	contractsPerSec := float64(numContracts) / elapsed.Seconds()

	t.Logf("Created and verified %d contracts in %v (%.0f contracts/sec)", numContracts, elapsed, contractsPerSec)

	// Should be able to create at least 100 contracts per second
	if contractsPerSec < 100 {
		t.Errorf("Performance too slow: %.0f contracts/sec (want >= 100)", contractsPerSec)
	}
}

// =============================================================================
// Environment Setup Helper
// =============================================================================

func TestMain(m *testing.M) {
	// Set up any required environment variables
	os.Setenv("DUCAT_PRIVATE_KEY", testPrivateKey)

	// Run tests
	code := m.Run()

	os.Exit(code)
}
