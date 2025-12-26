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

	// Build v3 PriceContract template (active quote with hidden secret)
	// Uses simpler core-ts PriceContract schema
	contractTemplate := PriceContract{
		// PriceOracleConfig
		ChainNetwork: wc.Config.Network,     // Bitcoin network
		OraclePubkey: keys.SchnorrPubkey,    // Server Schnorr public key
		// PriceObservation
		BasePrice:    currentPrice,          // Quote creation price
		BaseStamp:    quoteStamp,            // Quote creation timestamp
		// PriceContract specific
		CommitHash:   "",                    // Will be computed next
		ContractID:   "",                    // Will be computed next
		OracleSig:    "",                    // Will be computed next
		TholdHash:    tholdHash,             // Hash160 commitment
		TholdKey:     nil,                   // Secret is NOT revealed (null for active)
		TholdPrice:   tholdPrice,            // Threshold price
	}

	// Compute deterministic commit hash (hash340 of preimage)
	commitHash, err := computeCommitHash(requestData.Domain, &contractTemplate)
	if err != nil {
		return nil, fmt.Errorf("commit hash computation failed: %w", err)
	}

	// Compute contract ID (hash340 of commit||thold)
	contractID := commitHash // For now use commit hash as contract ID

	// Sign commit hash with Schnorr
	oracleSig, err := signSchnorr(keys.PrivateKey, commitHash)
	if err != nil {
		return nil, fmt.Errorf("signature failed: %w", err)
	}

	// Update template with computed values
	contractTemplate.CommitHash = commitHash
	contractTemplate.ContractID = contractID
	contractTemplate.OracleSig = oracleSig
	contractData := contractTemplate

	// Marshal to JSON for Nostr event content
	contractJSON, err := json.Marshal(contractData)
	if err != nil {
		return nil, fmt.Errorf("contract marshaling failed: %w", err)
	}

	// Create Nostr event
	nostrEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", tholdHash}, // NIP-33 replaceable event identifier
			{"domain", requestData.Domain},
			{"thold_price", fmt.Sprintf("%.8f", tholdPrice)},
		},
		Content: string(contractJSON),
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

	// Send webhook callback if URL provided (single node execution after consensus)
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, nostrEvent, "create")
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		// Await to ensure single execution, but ignore errors (best-effort)
		_, _ = webhookPromise.Await()
	}

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

	// Parse original event content as v3 PriceContract
	var originalData PriceContract
	if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
		return nil, fmt.Errorf("failed to parse original event: %w", err)
	}

	logger.Info("Fetched original quote", "basePrice", originalData.BasePrice, "tholdPrice", originalData.TholdPrice, "tholdHash", originalData.TholdHash)

	// Fetch current BTC/USD price with consensus
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	currentStamp := priceData.Stamp
	logger.Info("Fetched current price", "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

	// Validate quote age
	if err := validateQuoteAge(originalData.BaseStamp, currentStamp); err != nil {
		return nil, fmt.Errorf("quote validation failed: %w", err)
	}

	// Check if threshold breached (price fell below threshold)
	if currentPrice >= originalData.TholdPrice {
		logger.Info("Threshold NOT breached, returning original event", "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

		// Send webhook callback if URL provided (single node execution after consensus)
		if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
			webhookPromise := http.SendRequest(wc, runtime, client,
				func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
					sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, originalEvent, "check_no_breach")
					return &RelayResponse{Success: true, Message: "webhook sent"}, nil
				},
				cre.ConsensusAggregationFromTags[*RelayResponse](),
			)
			// Await to ensure single execution, but ignore errors (best-effort)
			_, _ = webhookPromise.Await()
		}

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
		originalData.BasePrice,
		originalData.BaseStamp,
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

	// Build v3 breach PriceContract template with REVEALED secret
	breachTemplate := PriceContract{
		// PriceOracleConfig
		ChainNetwork: originalData.ChainNetwork,  // Bitcoin network
		OraclePubkey: originalData.OraclePubkey,  // Server Schnorr public key
		// PriceObservation
		BasePrice:    originalData.BasePrice,     // Quote creation price
		BaseStamp:    originalData.BaseStamp,     // Quote creation timestamp
		// PriceContract specific
		CommitHash:   "",                         // Will be computed next
		ContractID:   "",                         // Will be computed next
		OracleSig:    "",                         // Will be computed next
		TholdHash:    originalData.TholdHash,     // Hash160 commitment
		TholdKey:     &tholdSecret,               // SECRET IS NOW REVEALED
		TholdPrice:   originalData.TholdPrice,    // Threshold price
	}

	// Compute deterministic commit hash
	breachCommitHash, err := computeCommitHash(requestData.Domain, &breachTemplate)
	if err != nil {
		return nil, fmt.Errorf("commit hash computation failed: %w", err)
	}

	// Sign commit hash with Schnorr
	breachOracleSig, err := signSchnorr(keys.PrivateKey, breachCommitHash)
	if err != nil {
		return nil, fmt.Errorf("signature failed: %w", err)
	}

	// Update template with computed values
	breachTemplate.CommitHash = breachCommitHash
	breachTemplate.ContractID = breachCommitHash // Use commit hash as contract ID
	breachTemplate.OracleSig = breachOracleSig
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

	// Send webhook callback if URL provided (single node execution after consensus)
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, breachEvent, "breach")
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		// Await to ensure single execution, but ignore errors (best-effort)
		_, _ = webhookPromise.Await()
	}

	return breachEvent, nil
}

// sendWebhookCallback sends HTTP POST notification to callback URL
// Notifies external systems of workflow completion with results
// This is a best-effort notification - failures are logged but don't block the workflow
func sendWebhookCallback(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, event *NostrEvent, eventType string) {
	logger.Info("Sending webhook callback", "url", callbackURL, "eventType", eventType)

	// Prepare callback payload
	callbackPayload := map[string]interface{}{
		"event_type":  eventType,
		"event_id":    event.ID,
		"pubkey":      event.PubKey,
		"created_at":  event.CreatedAt,
		"kind":        event.Kind,
		"tags":        event.Tags,
		"content":     event.Content,
		"sig":         event.Sig,
		"nostr_event": event,
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal callback payload", "error", err)
		return
	}

	// Send POST request to callback URL (no consensus required for notifications)
	resp, err := sendRequester.SendRequest(&http.Request{
		Url:    callbackURL,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: callbackJSON,
	}).Await()

	if err != nil {
		logger.Error("Webhook callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("Webhook callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("Webhook callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode, "body", string(resp.Body))
	}
}
