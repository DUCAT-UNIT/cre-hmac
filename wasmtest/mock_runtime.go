// Package wasmtest provides test infrastructure for WASM handlers
// Allows testing handler logic without requiring actual WASM/CRE execution
package wasmtest

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"sync"

	"ducat/crypto"
	"ducat/shared"
)

// MockLogger wraps slog for testing
type MockLogger struct {
	*slog.Logger
	Messages []LogMessage
	mu       sync.Mutex
}

// LogMessage records a log entry for testing
type LogMessage struct {
	Level   string
	Message string
	Args    []interface{}
}

// NewMockLogger returns a MockLogger that records log messages and wraps a slog.Logger.
// The returned logger uses a text handler that writes to stdout at debug level and
// initializes the in-memory Messages slice empty.
func NewMockLogger() *MockLogger {
	return &MockLogger{
		Logger:   slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug})),
		Messages: []LogMessage{},
	}
}

func (m *MockLogger) Info(msg string, args ...interface{}) {
	m.mu.Lock()
	m.Messages = append(m.Messages, LogMessage{Level: "INFO", Message: msg, Args: args})
	m.mu.Unlock()
	m.Logger.Info(msg, args...)
}

func (m *MockLogger) Error(msg string, args ...interface{}) {
	m.mu.Lock()
	m.Messages = append(m.Messages, LogMessage{Level: "ERROR", Message: msg, Args: args})
	m.mu.Unlock()
	m.Logger.Error(msg, args...)
}

func (m *MockLogger) Warn(msg string, args ...interface{}) {
	m.mu.Lock()
	m.Messages = append(m.Messages, LogMessage{Level: "WARN", Message: msg, Args: args})
	m.mu.Unlock()
	m.Logger.Warn(msg, args...)
}

// MockPriceData simulates Chainlink price data
type MockPriceData struct {
	Price  float64 `json:"price"`
	Origin string  `json:"origin"`
	Stamp  int64   `json:"stamp"`
}

// MockRelayClient simulates Nostr relay operations
type MockRelayClient struct {
	PublishedEvents        []*shared.NostrEvent
	StoredEvents           map[string]*shared.NostrEvent // keyed by d-tag (thold_hash)
	PublishError           error
	FetchError             error
	LatestQuoteTimestamp   int64 // Simulated latest quote timestamp for rate limiting
	LatestTimestampError   error // Error to return from GetLatestQuoteTimestamp
	mu                     sync.Mutex
}

// NewMockRelayClient returns a MockRelayClient initialized for testing.
// PublishedEvents is an empty slice and StoredEvents is an empty map ready to record events.
func NewMockRelayClient() *MockRelayClient {
	return &MockRelayClient{
		PublishedEvents: []*shared.NostrEvent{},
		StoredEvents:    make(map[string]*shared.NostrEvent),
	}
}

// PublishEvent simulates publishing an event
func (m *MockRelayClient) PublishEvent(event *shared.NostrEvent) (*shared.RelayResponse, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.PublishError != nil {
		return &shared.RelayResponse{Success: false, Message: m.PublishError.Error()}, m.PublishError
	}

	m.PublishedEvents = append(m.PublishedEvents, event)

	// Store by d-tag if present
	for _, tag := range event.Tags {
		if len(tag) >= 2 && tag[0] == "d" {
			m.StoredEvents[tag[1]] = event
			break
		}
	}

	return &shared.RelayResponse{Success: true, Message: "OK"}, nil
}

// FetchByDTag simulates fetching an event by d-tag
func (m *MockRelayClient) FetchByDTag(dTag string) (*shared.NostrEvent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.FetchError != nil {
		return nil, m.FetchError
	}

	event, ok := m.StoredEvents[dTag]
	if !ok {
		return nil, fmt.Errorf("event not found for d-tag: %s", dTag)
	}

	return event, nil
}

// GetLatestQuoteTimestamp simulates fetching the latest quote timestamp for rate limiting
func (m *MockRelayClient) GetLatestQuoteTimestamp(oraclePubkey string) (int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.LatestTimestampError != nil {
		return 0, m.LatestTimestampError
	}

	// If LatestQuoteTimestamp is set, return it
	if m.LatestQuoteTimestamp > 0 {
		return m.LatestQuoteTimestamp, nil
	}

	// Otherwise, find the most recent event by this pubkey
	var latest int64
	for _, event := range m.StoredEvents {
		if event.PubKey == oraclePubkey && event.CreatedAt > latest {
			latest = event.CreatedAt
		}
	}

	return latest, nil
}

// MockPriceClient simulates price data fetching
type MockPriceClient struct {
	Price float64
	Stamp int64
	Error error
}

// NewMockPriceClient returns a MockPriceClient initialized with the provided price and timestamp for use in tests.
// The created client will return the configured price and stamp from FetchPrice unless its Error field is set.
func NewMockPriceClient(price float64, stamp int64) *MockPriceClient {
	return &MockPriceClient{
		Price: price,
		Stamp: stamp,
	}
}

// FetchPrice simulates fetching current price
func (m *MockPriceClient) FetchPrice() (*MockPriceData, error) {
	if m.Error != nil {
		return nil, m.Error
	}
	return &MockPriceData{
		Price:  m.Price,
		Origin: "mock-chainlink",
		Stamp:  m.Stamp,
	}, nil
}

// MockWebhookClient simulates webhook callbacks
type MockWebhookClient struct {
	Callbacks []WebhookCallback
	Error     error
	mu        sync.Mutex
}

// WebhookCallback records a webhook call
type WebhookCallback struct {
	URL     string
	Payload map[string]interface{}
}

// NewMockWebhookClient returns a MockWebhookClient with an initialized empty Callbacks slice.
// The returned client is ready for use; Error is nil and the internal mutex is in its zero value.
func NewMockWebhookClient() *MockWebhookClient {
	return &MockWebhookClient{
		Callbacks: []WebhookCallback{},
	}
}

// SendCallback simulates sending a webhook callback
func (m *MockWebhookClient) SendCallback(url string, payload map[string]interface{}) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.Error != nil {
		return m.Error
	}

	m.Callbacks = append(m.Callbacks, WebhookCallback{
		URL:     url,
		Payload: payload,
	})
	return nil
}

// WorkflowSimulator simulates CRE workflow execution
type WorkflowSimulator struct {
	Config        *shared.Config
	PrivateKey    string
	PriceClient   *MockPriceClient
	RelayClient   *MockRelayClient
	WebhookClient *MockWebhookClient
	Logger        *MockLogger
}

// NewWorkflowSimulator returns a WorkflowSimulator preconfigured with a default test Config and in-memory mock clients for price, relay, webhook, and logging.
// The provided privateKey is stored in the simulator and used for key derivation during simulated workflows.
func NewWorkflowSimulator(privateKey string) *WorkflowSimulator {
	return &WorkflowSimulator{
		Config: &shared.Config{
			ClientID:      "test-client",
			DataStreamURL: "https://test.data.stream",
			FeedID:        "BTC/USD",
			RelayURL:      "wss://test.relay",
			Network:       "mutiny",
		},
		PrivateKey:    privateKey,
		PriceClient:   NewMockPriceClient(100000, 1700000000),
		RelayClient:   NewMockRelayClient(),
		WebhookClient: NewMockWebhookClient(),
		Logger:        NewMockLogger(),
	}
}

// SimulateCreateQuote simulates the createQuote handler
func (w *WorkflowSimulator) SimulateCreateQuote(domain string, tholdPrice float64) (*shared.NostrEvent, error) {
	// Derive keys
	kd, err := crypto.DeriveKeys(w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch price
	priceData, err := w.PriceClient.FetchPrice()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice := priceData.Price

	// Validate threshold distance
	if tholdPrice > currentPrice {
		minThreshold := currentPrice * (1 + shared.MinThresholdDistance)
		if tholdPrice < minThreshold {
			return nil, fmt.Errorf("threshold too close to current price (above): min %.2f, got %.2f", minThreshold, tholdPrice)
		}
	} else {
		maxThreshold := currentPrice * (1 - shared.MinThresholdDistance)
		if tholdPrice > maxThreshold {
			return nil, fmt.Errorf("threshold too close to current price (below): max %.2f, got %.2f", maxThreshold, tholdPrice)
		}
	}

	// Create price contract
	contract, err := crypto.CreatePriceContract(
		w.PrivateKey,
		crypto.PriceObservation{
			OraclePubkey: kd.SchnorrPubkey,
			ChainNetwork: w.Config.Network,
			BasePrice:    uint32(currentPrice),
			BaseStamp:    uint32(priceData.Stamp),
		},
		uint32(tholdPrice),
	)
	if err != nil {
		return nil, fmt.Errorf("price contract creation failed: %w", err)
	}

	// Sign contract ID
	oracleSig, err := crypto.SignSchnorr(kd.PrivateKey, contract.ContractID)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Build PriceEvent
	eventData := shared.PriceEvent{
		EventType:    shared.EventTypeActive,
		LatestOrigin: priceData.Origin,
		LatestPrice:  currentPrice,
		LatestStamp:  priceData.Stamp,
		QuoteOrigin:  priceData.Origin,
		QuotePrice:   currentPrice,
		QuoteStamp:   priceData.Stamp,
		ChainNetwork: w.Config.Network,
		OraclePubkey: kd.SchnorrPubkey,
		BasePrice:    int64(currentPrice),
		BaseStamp:    priceData.Stamp,
		CommitHash:   contract.CommitHash,
		ContractID:   contract.ContractID,
		OracleSig:    oracleSig,
		TholdHash:    contract.TholdHash,
		TholdKey:     nil,
		TholdPrice:   tholdPrice,
		IsExpired:    false,
		SrvNetwork:   w.Config.Network,
		SrvPubkey:    kd.SchnorrPubkey,
		ReqID:        contract.ContractID,
		ReqSig:       oracleSig,
	}

	eventJSON, _ := json.Marshal(eventData)

	// Create Nostr event
	nostrEvent := &shared.NostrEvent{
		PubKey:    kd.SchnorrPubkey,
		CreatedAt: priceData.Stamp,
		Kind:      shared.NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", contract.TholdHash},
			{"domain", domain},
			{"event_type", shared.EventTypeActive},
			{"thold_price", fmt.Sprintf("%.8f", tholdPrice)},
		},
		Content: string(eventJSON),
	}

	// Sign Nostr event
	if err := signNostrEvent(nostrEvent, kd.PrivateKey); err != nil {
		return nil, fmt.Errorf("event signing failed: %w", err)
	}

	// Publish to mock relay
	_, err = w.RelayClient.PublishEvent(nostrEvent)
	if err != nil {
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	return nostrEvent, nil
}

// SimulateCheckQuote simulates the checkQuote handler
func (w *WorkflowSimulator) SimulateCheckQuote(domain string, tholdHash string) (*shared.NostrEvent, error) {
	// Derive keys
	kd, err := crypto.DeriveKeys(w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch original event
	originalEvent, err := w.RelayClient.FetchByDTag(tholdHash)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch original event: %w", err)
	}

	// Parse original event content
	var originalData shared.PriceEvent
	if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
		return nil, fmt.Errorf("failed to parse original event: %w", err)
	}

	// Fetch current price
	priceData, err := w.PriceClient.FetchPrice()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice := priceData.Price

	// Check if threshold breached
	if currentPrice >= originalData.TholdPrice {
		// Not breached - return original event
		return originalEvent, nil
	}

	// BREACHED - regenerate secret and reveal
	obs := crypto.PriceObservation{
		OraclePubkey: originalData.SrvPubkey,
		ChainNetwork: originalData.SrvNetwork,
		BasePrice:    uint32(originalData.QuotePrice),
		BaseStamp:    uint32(originalData.QuoteStamp),
	}

	commitHash, err := crypto.GetPriceCommitHash(obs, uint32(originalData.TholdPrice))
	if err != nil {
		return nil, fmt.Errorf("commit hash regeneration failed: %w", err)
	}

	tholdSecret, err := crypto.GetTholdKey(w.PrivateKey, commitHash)
	if err != nil {
		return nil, fmt.Errorf("threshold key regeneration failed: %w", err)
	}

	// Verify commitment
	if err := crypto.VerifyThresholdCommitment(tholdSecret, originalData.TholdHash); err != nil {
		return nil, fmt.Errorf("commitment verification failed: %w", err)
	}

	// Compute contract ID
	contractID, err := crypto.GetPriceContractID(commitHash, originalData.TholdHash)
	if err != nil {
		return nil, fmt.Errorf("contract ID computation failed: %w", err)
	}

	// Sign contract ID
	oracleSig, err := crypto.SignSchnorr(kd.PrivateKey, contractID)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Build breach event
	breachData := shared.PriceEvent{
		EventOrigin:  &priceData.Origin,
		EventPrice:   &currentPrice,
		EventStamp:   &priceData.Stamp,
		EventType:    shared.EventTypeBreach,
		LatestOrigin: priceData.Origin,
		LatestPrice:  currentPrice,
		LatestStamp:  priceData.Stamp,
		QuoteOrigin:  originalData.QuoteOrigin,
		QuotePrice:   originalData.QuotePrice,
		QuoteStamp:   originalData.QuoteStamp,
		ChainNetwork: originalData.ChainNetwork,
		OraclePubkey: originalData.OraclePubkey,
		BasePrice:    originalData.BasePrice,
		BaseStamp:    originalData.BaseStamp,
		CommitHash:   commitHash,
		ContractID:   contractID,
		OracleSig:    oracleSig,
		TholdHash:    originalData.TholdHash,
		TholdKey:     &tholdSecret,
		TholdPrice:   originalData.TholdPrice,
		IsExpired:    true,
		SrvNetwork:   originalData.SrvNetwork,
		SrvPubkey:    originalData.SrvPubkey,
		ReqID:        contractID,
		ReqSig:       oracleSig,
	}

	breachJSON, _ := json.Marshal(breachData)

	breachEvent := &shared.NostrEvent{
		PubKey:    kd.SchnorrPubkey,
		CreatedAt: priceData.Stamp,
		Kind:      shared.NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", originalData.TholdHash},
			{"domain", domain},
			{"event_type", shared.EventTypeBreach},
			{"original_event", originalEvent.ID},
			{"thold_price", fmt.Sprintf("%.8f", originalData.TholdPrice)},
			{"breach_price", fmt.Sprintf("%.8f", currentPrice)},
		},
		Content: string(breachJSON),
	}

	if err := signNostrEvent(breachEvent, kd.PrivateKey); err != nil {
		return nil, fmt.Errorf("breach event signing failed: %w", err)
	}

	// Publish breach event
	_, err = w.RelayClient.PublishEvent(breachEvent)
	if err != nil {
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	return breachEvent, nil
}

// SimulateEvaluateQuotes simulates the evaluateQuotes handler
func (w *WorkflowSimulator) SimulateEvaluateQuotes(tholdHashes []string) (*shared.EvaluateQuotesResponse, error) {
	// Derive keys
	kd, err := crypto.DeriveKeys(w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch current price once
	priceData, err := w.PriceClient.FetchPrice()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice := priceData.Price
	currentStamp := priceData.Stamp

	results := make([]shared.QuoteEvaluationResult, len(tholdHashes))

	for i, tholdHash := range tholdHashes {
		result := shared.QuoteEvaluationResult{
			TholdHash:    tholdHash,
			CurrentPrice: currentPrice,
		}

		// Fetch original event
		originalEvent, err := w.RelayClient.FetchByDTag(tholdHash)
		if err != nil {
			errMsg := fmt.Sprintf("failed to fetch quote: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		// Parse original event
		var originalData shared.PriceEvent
		if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
			errMsg := fmt.Sprintf("failed to parse quote: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		result.TholdPrice = originalData.TholdPrice

		// Check if already breached
		if originalData.EventType == shared.EventTypeBreach {
			result.Status = "breached"
			result.TholdKey = originalData.TholdKey
			results[i] = result
			continue
		}

		// Check breach condition
		if currentPrice >= originalData.TholdPrice {
			result.Status = "active"
			results[i] = result
			continue
		}

		// BREACHED - generate secret and publish
		obs := crypto.PriceObservation{
			OraclePubkey: originalData.SrvPubkey,
			ChainNetwork: originalData.SrvNetwork,
			BasePrice:    uint32(originalData.QuotePrice),
			BaseStamp:    uint32(originalData.QuoteStamp),
		}

		commitHash, err := crypto.GetPriceCommitHash(obs, uint32(originalData.TholdPrice))
		if err != nil {
			errMsg := fmt.Sprintf("commit hash failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}
		tholdSecret, err := crypto.GetTholdKey(w.PrivateKey, commitHash)
		if err != nil {
			errMsg := fmt.Sprintf("thold key failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}
		contractID, err := crypto.GetPriceContractID(commitHash, originalData.TholdHash)
		if err != nil {
			errMsg := fmt.Sprintf("contract ID failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}
		oracleSig, err := crypto.SignSchnorr(kd.PrivateKey, contractID)
		if err != nil {
			errMsg := fmt.Sprintf("signing failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		// Build and publish breach event
		breachData := shared.PriceEvent{
			EventOrigin:  &priceData.Origin,
			EventPrice:   &currentPrice,
			EventStamp:   &currentStamp,
			EventType:    shared.EventTypeBreach,
			LatestOrigin: priceData.Origin,
			LatestPrice:  currentPrice,
			LatestStamp:  currentStamp,
			QuoteOrigin:  originalData.QuoteOrigin,
			QuotePrice:   originalData.QuotePrice,
			QuoteStamp:   originalData.QuoteStamp,
			ChainNetwork: originalData.ChainNetwork,
			OraclePubkey: originalData.OraclePubkey,
			BasePrice:    originalData.BasePrice,
			BaseStamp:    originalData.BaseStamp,
			CommitHash:   commitHash,
			ContractID:   contractID,
			OracleSig:    oracleSig,
			TholdHash:    originalData.TholdHash,
			TholdKey:     &tholdSecret,
			TholdPrice:   originalData.TholdPrice,
			IsExpired:    true,
			SrvNetwork:   originalData.SrvNetwork,
			SrvPubkey:    originalData.SrvPubkey,
			ReqID:        contractID,
			ReqSig:       oracleSig,
		}

		breachJSON, _ := json.Marshal(breachData)
		breachEvent := &shared.NostrEvent{
			PubKey:    kd.SchnorrPubkey,
			CreatedAt: currentStamp,
			Kind:      shared.NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", originalData.TholdHash},
				{"domain", "batch-evaluate"},
				{"event_type", shared.EventTypeBreach},
				{"thold_price", fmt.Sprintf("%.8f", originalData.TholdPrice)},
				{"breach_price", fmt.Sprintf("%.8f", currentPrice)},
			},
			Content: string(breachJSON),
		}
		signNostrEvent(breachEvent, kd.PrivateKey)
		w.RelayClient.PublishEvent(breachEvent)

		result.Status = "breached"
		result.TholdKey = &tholdSecret
		results[i] = result
	}

	return &shared.EvaluateQuotesResponse{
		Results:      results,
		CurrentPrice: currentPrice,
		EvaluatedAt:  currentStamp,
	}, nil
}

// SimulateGenerateQuotes simulates the generateQuotes handler
func (w *WorkflowSimulator) SimulateGenerateQuotes(req *shared.GenerateQuotesRequest) (*shared.GenerateQuotesResponse, error) {
	// Derive keys
	kd, err := crypto.DeriveKeys(w.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch current price once
	priceData, err := w.PriceClient.FetchPrice()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice := priceData.Price
	quoteStamp := priceData.Stamp

	quoteDomainPrefix := req.GetQuoteDomain()

	var tholdHashes []string
	var minThold, maxThold float64
	quotesCreated := 0

	for rate := req.RateMin; rate <= req.RateMax+0.0001; rate += req.StepSize {
		tholdPrice := currentPrice * rate

		if minThold == 0 || tholdPrice < minThold {
			minThold = tholdPrice
		}
		if tholdPrice > maxThold {
			maxThold = tholdPrice
		}

		domain := fmt.Sprintf("%s-%.2f", quoteDomainPrefix, rate)

		contract, err := crypto.CreatePriceContract(
			w.PrivateKey,
			crypto.PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: w.Config.Network,
				BasePrice:    uint32(currentPrice),
				BaseStamp:    uint32(quoteStamp),
			},
			uint32(tholdPrice),
		)
		if err != nil {
			continue
		}

		oracleSig, err := crypto.SignSchnorr(kd.PrivateKey, contract.ContractID)
		if err != nil {
			continue
		}

		eventData := shared.PriceEvent{
			EventType:    shared.EventTypeActive,
			LatestOrigin: priceData.Origin,
			LatestPrice:  currentPrice,
			LatestStamp:  priceData.Stamp,
			QuoteOrigin:  priceData.Origin,
			QuotePrice:   currentPrice,
			QuoteStamp:   quoteStamp,
			ChainNetwork: w.Config.Network,
			OraclePubkey: kd.SchnorrPubkey,
			BasePrice:    int64(currentPrice),
			BaseStamp:    quoteStamp,
			CommitHash:   contract.CommitHash,
			ContractID:   contract.ContractID,
			OracleSig:    oracleSig,
			TholdHash:    contract.TholdHash,
			TholdPrice:   tholdPrice,
			IsExpired:    false,
			SrvNetwork:   w.Config.Network,
			SrvPubkey:    kd.SchnorrPubkey,
			ReqID:        contract.ContractID,
			ReqSig:       oracleSig,
		}

		eventJSON, _ := json.Marshal(eventData)

		nostrEvent := &shared.NostrEvent{
			PubKey:    kd.SchnorrPubkey,
			CreatedAt: quoteStamp,
			Kind:      shared.NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", contract.TholdHash},
				{"domain", domain},
				{"event_type", shared.EventTypeActive},
				{"thold_price", fmt.Sprintf("%.8f", tholdPrice)},
				{"rate", fmt.Sprintf("%.4f", rate)},
			},
			Content: string(eventJSON),
		}

		signNostrEvent(nostrEvent, kd.PrivateKey)
		w.RelayClient.PublishEvent(nostrEvent)

		tholdHashes = append(tholdHashes, contract.TholdHash)
		quotesCreated++
	}

	response := &shared.GenerateQuotesResponse{
		QuotesCreated: quotesCreated,
		CurrentPrice:  currentPrice,
		TholdHashes:   tholdHashes,
		GeneratedAt:   quoteStamp,
	}
	response.Range.MinThold = minThold
	response.Range.MaxThold = maxThold

	return response, nil
}