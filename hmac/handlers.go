//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// Request handlers for DUCAT threshold commitment system
//
// CREATE: New threshold quote with HMAC-derived secret
// CHECK: Monitor quote, reveal secret on threshold breach
//
// Uses DON consensus for price data and relay operations

// createQuote creates new price threshold commitment
// 1. Fetch BTC/USD price with DON consensus
// 2. Validate threshold distance (1% min)
// 3. Derive threshold secret via HMAC
// 4. Compute Hash160 commitment
// 5. Sign and publish Nostr event (NIP-33)
func createQuote(wc *WorkflowConfig, runtime cre.Runtime, requestData *HttpRequestData) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("Creating new quote", "domain", requestData.Domain, "tholdPrice", *requestData.TholdPrice)

	// Derive keys from private key (from secrets)
	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch current BTC/USD price with consensus
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	tholdPrice := *requestData.TholdPrice

	logger.Info("Fetched current price", "currentPrice", currentPrice, "tholdPrice", tholdPrice)

	// Validate threshold is not too close to current price
	// Two modes supported:
	// 1. Threshold > current: Immediate breach (testing/conditional release)
	// 2. Threshold < current: Delayed breach (downside protection)
	// For meaningful behavior, require at least 1% distance in either direction
	if tholdPrice > currentPrice {
		// Threshold above current (immediate breach mode)
		minThreshold := currentPrice * (1 + MinThresholdDistance)
		if tholdPrice < minThreshold {
			return nil, fmt.Errorf("threshold too close to current price (above): min %.2f, got %.2f", minThreshold, tholdPrice)
		}
	} else {
		// Threshold below current (downside protection mode)
		maxThreshold := currentPrice * (1 - MinThresholdDistance)
		if tholdPrice > maxThreshold {
			return nil, fmt.Errorf("threshold too close to current price (below): max %.2f, got %.2f", maxThreshold, tholdPrice)
		}
	}

	// Use price timestamp from data stream (DON consensus time via data)
	quoteStamp := priceData.Stamp

	// Generate server HMAC key (using private key from secrets)
	serverHMAC, err := getServerHMAC(wc.PrivateKey, requestData.Domain)
	if err != nil {
		return nil, fmt.Errorf("server HMAC generation failed: %w", err)
	}

	// Generate threshold secret key
	tholdSecret, err := getThresholdKey(serverHMAC, requestData.Domain, currentPrice, quoteStamp, tholdPrice)
	if err != nil {
		return nil, fmt.Errorf("threshold key generation failed: %w", err)
	}

	// Compute Hash160 commitment
	tholdHash, err := hash160([]byte(tholdSecret))
	if err != nil {
		return nil, fmt.Errorf("hash160 failed: %w", err)
	}

	// Build PriceEvent template (active quote with hidden secret)
	// Event fields are nil for active quotes (not breached yet)
	// This matches price-oracle's EventActiveQuote structure
	eventTemplate := PriceEvent{
		EventOrigin:  nil,               // No breach yet (null for active)
		EventPrice:   nil,               // No breach yet (null for active)
		EventStamp:   nil,               // No breach yet (null for active)
		EventType:    EventTypeActive,   // "active"
		LatestOrigin: priceData.Origin,  // current price origin
		LatestPrice:  currentPrice,      // current price
		LatestStamp:  priceData.Stamp,   // current timestamp
		QuoteOrigin:  priceData.Origin,  // quote creation origin
		QuotePrice:   currentPrice,      // quote creation price
		QuoteStamp:   quoteStamp,             // quote creation timestamp
		IsExpired:    false,                  // not expired (active quote)
		SrvNetwork:   wc.Config.Network,      // Bitcoin network
		SrvPubkey:    keys.SchnorrPubkey, // Server Schnorr public key
		TholdHash:    tholdHash,         // Hash160 commitment
		TholdKey:     "",                // Secret is NOT revealed (empty for active)
		TholdPrice:   tholdPrice,        // Threshold price
		ReqID:        "",                // Will be computed next
		ReqSig:       "",                // Will be computed next
	}

	// Compute deterministic request ID from complete template
	// This matches price-oracle's get_event_quote_request_id
	reqID, err := computeRequestID(requestData.Domain, &eventTemplate)
	if err != nil {
		return nil, fmt.Errorf("request ID computation failed: %w", err)
	}

	// Sign request ID with Schnorr
	reqSig, err := signSchnorr(keys.PrivateKey, reqID)
	if err != nil {
		return nil, fmt.Errorf("request signing failed: %w", err)
	}

	// Update template with req_id and req_sig
	eventTemplate.ReqID = reqID
	eventTemplate.ReqSig = reqSig
	eventData := eventTemplate

	// Marshal to JSON for Nostr event content
	eventJSON, err := json.Marshal(eventData)
	if err != nil {
		return nil, fmt.Errorf("event marshaling failed: %w", err)
	}

	// Create Nostr event
	nostrEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", tholdHash}, // NIP-33 replaceable event identifier
			{"domain", requestData.Domain},
			{"event_type", EventTypeActive},
			{"thold_price", fmt.Sprintf("%.8f", tholdPrice)},
		},
		Content: string(eventJSON),
	}

	// Sign Nostr event
	if err := signNostrEvent(nostrEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("event signing failed: %w", err)
	}

	logger.Info("Created quote", "eventId", nostrEvent.ID, "tholdHash", tholdHash)

	// Publish to relay with consensus
	relayRespPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishEvent(wc.Config, log, sr, nostrEvent)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := relayRespPromise.Await()
	if err != nil {
		logger.Error("Failed to publish to relay", "error", err)
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected event: %s", relayResp.Message)
	}

	logger.Info("Successfully published quote to relay", "eventId", nostrEvent.ID)

	return nostrEvent, nil
}

// checkQuote monitors quote and reveals secret on breach
// 1. Fetch quote from relay by threshold hash
// 2. Fetch current BTC/USD price
// 3. Check breach condition (currentPrice < threshold)
// 4. If breached: regenerate secret, verify commitment, publish breach event
// 5. If not breached: return original event
func checkQuote(wc *WorkflowConfig, runtime cre.Runtime, requestData *HttpRequestData) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("Checking quote", "domain", requestData.Domain, "tholdHash", *requestData.TholdHash)

	// Derive keys (from secrets)
	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}

	// Fetch original event from relay by d tag (thold_hash) with consensus
	client := &http.Client{}
	originalEventPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*NostrEvent, error) {
			return fetchEventByDTag(wc.Config, log, sr, *requestData.TholdHash)
		},
		cre.ConsensusIdenticalAggregation[*NostrEvent](),
	)

	originalEvent, err := originalEventPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch original event: %w", err)
	}

	// Parse original event content
	var originalData PriceEvent
	if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
		return nil, fmt.Errorf("failed to parse original event: %w", err)
	}

	logger.Info("Fetched original quote", "quotePrice", originalData.QuotePrice, "tholdPrice", originalData.TholdPrice, "tholdHash", originalData.TholdHash)

	// Validate quote age (using latest stamp from data)
	if err := validateQuoteAge(originalData.QuoteStamp, originalData.LatestStamp); err != nil {
		return nil, fmt.Errorf("quote validation failed: %w", err)
	}

	// Fetch current BTC/USD price with consensus
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	currentStamp := priceData.Stamp
	logger.Info("Fetched current price", "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

	// Check if threshold breached (price fell below threshold)
	if currentPrice >= originalData.TholdPrice {
		logger.Info("Threshold NOT breached, returning original event", "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)
		return originalEvent, nil
	}

	// Threshold BREACHED - regenerate secret and reveal it
	logger.Info("THRESHOLD BREACHED - revealing secret", "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

	// Regenerate server HMAC (using private key from secrets)
	serverHMAC, err := getServerHMAC(wc.PrivateKey, requestData.Domain)
	if err != nil {
		return nil, fmt.Errorf("server HMAC regeneration failed: %w", err)
	}

	// Regenerate threshold secret (should match original)
	tholdSecret, err := getThresholdKey(
		serverHMAC,
		requestData.Domain,
		originalData.QuotePrice,
		originalData.QuoteStamp,
		originalData.TholdPrice,
	)
	if err != nil {
		return nil, fmt.Errorf("threshold key regeneration failed: %w", err)
	}

	// Verify secret matches original commitment
	if err := verifyThresholdCommitment(tholdSecret, originalData.TholdHash); err != nil {
		logger.Error("Commitment verification failed", "error", err)
		return nil, fmt.Errorf("commitment verification failed: %w", err)
	}

	logger.Info("Commitment verified successfully")

	// Build breach PriceEvent template with REVEALED secret
	// Event fields are now populated with breach data
	// This matches price-oracle's EventExpiredQuote structure
	breachTemplate := PriceEvent{
		EventOrigin:  &priceData.Origin,         // Breach origin (populated for expired)
		EventPrice:   &currentPrice,             // Breach price (populated for expired)
		EventStamp:   &currentStamp,             // Breach timestamp (populated for expired)
		EventType:    EventTypeBreach,           // "breach"
		LatestOrigin: priceData.Origin,          // current price origin
		LatestPrice:  currentPrice,              // current price
		LatestStamp:  currentStamp,              // current timestamp
		QuoteOrigin:  originalData.QuoteOrigin,  // quote creation origin
		QuotePrice:   originalData.QuotePrice,   // quote creation price
		QuoteStamp:   originalData.QuoteStamp,   // quote creation timestamp
		IsExpired:    true,                      // expired (breached quote)
		SrvNetwork:   originalData.SrvNetwork,   // Bitcoin network
		SrvPubkey:    originalData.SrvPubkey,    // Server Schnorr public key
		TholdHash:    originalData.TholdHash,    // Hash160 commitment
		TholdKey:     tholdSecret,               // SECRET IS NOW REVEALED
		TholdPrice:   originalData.TholdPrice,   // Threshold price
		ReqID:        "",                        // Will be computed next
		ReqSig:       "",                        // Will be computed next
	}

	// Compute deterministic request ID from complete template
	reqID, err := computeRequestID(requestData.Domain, &breachTemplate)
	if err != nil {
		return nil, fmt.Errorf("request ID computation failed: %w", err)
	}

	// Sign request ID with Schnorr
	reqSig, err := signSchnorr(keys.PrivateKey, reqID)
	if err != nil {
		return nil, fmt.Errorf("request signing failed: %w", err)
	}

	// Update template with req_id and req_sig
	breachTemplate.ReqID = reqID
	breachTemplate.ReqSig = reqSig
	breachData := breachTemplate

	// Marshal to JSON
	breachJSON, err := json.Marshal(breachData)
	if err != nil {
		return nil, fmt.Errorf("breach event marshaling failed: %w", err)
	}

	// Create Nostr breach event
	breachEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: currentStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", originalData.TholdHash}, // Same d tag as original - replaces it
			{"domain", requestData.Domain},
			{"event_type", EventTypeBreach},
			{"original_event", originalEvent.ID},
			{"thold_price", fmt.Sprintf("%.8f", originalData.TholdPrice)},
			{"breach_price", fmt.Sprintf("%.8f", currentPrice)},
		},
		Content: string(breachJSON),
	}

	// Sign breach event
	if err := signNostrEvent(breachEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("breach event signing failed: %w", err)
	}

	logger.Info("Created breach event", "eventId", breachEvent.ID, "secretRevealed", tholdSecret[:16]+"...")

	// Publish breach event to relay with consensus
	relayRespPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishEvent(wc.Config, log, sr, breachEvent)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := relayRespPromise.Await()
	if err != nil {
		logger.Error("Failed to publish breach event to relay", "error", err)
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected breach event: %s", relayResp.Message)
	}

	logger.Info("Successfully published breach event to relay", "eventId", breachEvent.ID)

	return breachEvent, nil
}
