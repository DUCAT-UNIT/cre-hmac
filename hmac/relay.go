//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
)

// Nostr relay interaction for quote publishing and querying
// Events verified with Schnorr signatures

// publishEvent publishes signed NIP-33 event to relay
func publishEvent(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, event *NostrEvent) (*RelayResponse, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if event == nil {
		return nil, fmt.Errorf("event cannot be nil")
	}
	if event.ID == "" {
		return nil, fmt.Errorf("event ID cannot be empty")
	}
	if event.Sig == "" {
		return nil, fmt.Errorf("event signature cannot be empty")
	}

	apiURL := strings.Replace(config.RelayURL, "ws://", "http://", 1)
	apiURL = strings.Replace(apiURL, "wss://", "https://", 1)
	apiURL = apiURL + "/api/quotes"

	logger.Info("Publishing event to relay", "url", apiURL, "eventId", event.ID)

	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "POST",
		Url:    apiURL,
		Body:   eventJSON,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}).Await()

	if err != nil {
		logger.Error("Failed to publish to relay", "error", err)
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		logger.Error("Non-success status from relay", "status", resp.StatusCode, "body", string(resp.Body))
		return &RelayResponse{
			Success: false,
			Message: fmt.Sprintf("relay returned status %d: %s", resp.StatusCode, string(resp.Body)),
		}, nil
	}

	logger.Info("Successfully published event to relay", "eventId", event.ID)

	return &RelayResponse{
		Success: true,
		Message: "Event published successfully",
	}, nil
}

// BatchFetchResult represents the fetch result for a single d tag
type BatchFetchResult struct {
	DTag  string     `json:"d_tag"`
	Event NostrEvent `json:"event,omitempty"`
	Error *string    `json:"error,omitempty"`
}

func relayBaseAPIURL(relayURL string) string {
	apiURL := strings.Replace(relayURL, "ws://", "http://", 1)
	return strings.Replace(apiURL, "wss://", "https://", 1)
}

// fetchEventByDTag retrieves a single quote by d-tag from the relay.
//
// SECURITY (M7): oraclePubkey MUST be the oracle's own Schnorr pubkey. Quotes
// are published by this workflow signing with its own key, so a legitimate quote
// event always has PubKey == oraclePubkey. We pin the relay /api/query filter to
// that author AND, defense in depth against a malicious/buggy relay that ignores
// the filter, re-check event.PubKey before (alongside) the existing signature
// verification. Without this, any party able to publish a kind-30078 event to
// the relay under a colliding d-tag could feed a forged quote into the money
// path. An empty oraclePubkey is a programming error (callers must always pass
// keys.SchnorrPubkey) and is rejected fail-closed.
func fetchEventByDTag(config *Config, _ *slog.Logger, sendRequester *http.SendRequester, dTag string, oraclePubkey string) (*BatchFetchResult, error) {
	result := &BatchFetchResult{DTag: dTag}

	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if oraclePubkey == "" {
		// Fail closed: never read a quote without an author to pin.
		errMsg := "oracle pubkey required to pin quote author"
		result.Error = &errMsg
		return result, nil
	}
	if dTag == "" {
		errMsg := "d tag cannot be empty"
		result.Error = &errMsg
		return result, nil
	}
	if !IsValidQuoteLookupDTag(dTag) {
		errMsg := fmt.Sprintf("invalid d tag: must be 40-char thold_hash or 64-char commit_hash (lowercase hex), got %q", dTag)
		result.Error = &errMsg
		return result, nil
	}

	apiURL := relayBaseAPIURL(config.RelayURL) + "/api/query"
	filter := map[string]interface{}{
		"kinds":   []int{30078},
		"#d":      []string{dTag},
		"authors": []string{oraclePubkey},
		"limit":   1,
	}

	reqJSON, err := json.Marshal(filter)
	if err != nil {
		errMsg := fmt.Sprintf("failed to marshal query request: %v", err)
		result.Error = &errMsg
		return result, nil
	}

	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "POST",
		Url:    apiURL,
		Body:   reqJSON,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}).Await()
	if err != nil {
		errMsg := fmt.Sprintf("query request failed: %v", err)
		result.Error = &errMsg
		return result, nil
	}

	if resp.StatusCode != 200 {
		errMsg := fmt.Sprintf("query returned status %d", resp.StatusCode)
		result.Error = &errMsg
		return result, nil
	}

	var events []NostrEvent
	if err := json.Unmarshal(resp.Body, &events); err != nil {
		errMsg := fmt.Sprintf("failed to parse query response: %v", err)
		result.Error = &errMsg
		return result, nil
	}
	if len(events) == 0 {
		errMsg := "event not found"
		result.Error = &errMsg
		return result, nil
	}

	event := events[0]
	// SECURITY (M7): defense in depth against a relay that ignores the authors
	// filter — re-check the author before trusting the event content.
	if event.PubKey != oraclePubkey {
		errMsg := fmt.Sprintf("quote from unexpected author %q", event.PubKey)
		result.Error = &errMsg
		return result, nil
	}
	if err := verifyNostrEvent(&event); err != nil {
		errMsg := fmt.Sprintf("signature verification failed: %v", err)
		result.Error = &errMsg
		return result, nil
	}

	result.Event = event
	return result, nil
}

// BatchPublishRequest is the request body for batch publishing multiple events
type BatchPublishRequest struct {
	Events []*NostrEvent `json:"events"`
}

// BatchPublishResponse is the response from batch publishing
type BatchPublishResponse struct {
	Success   bool   `json:"success" consensus_aggregation:"identical"`
	Published int    `json:"published" consensus_aggregation:"median"`
	Failed    int    `json:"failed" consensus_aggregation:"median"`
	Message   string `json:"message" consensus_aggregation:"identical"`
}

// MaxEventsPerBatch is the maximum number of events per HTTP request
const MaxEventsPerBatch = 70

// publishEventsBatch publishes multiple signed NIP-33 events to relay in a single request
func publishEventsBatch(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, events []*NostrEvent) (*BatchPublishResponse, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if len(events) == 0 {
		return &BatchPublishResponse{
			Success:   true,
			Published: 0,
			Failed:    0,
			Message:   "No events to publish",
		}, nil
	}

	for i, event := range events {
		if event == nil {
			return nil, fmt.Errorf("event at index %d cannot be nil", i)
		}
		if event.ID == "" {
			return nil, fmt.Errorf("event at index %d has empty ID", i)
		}
		if event.Sig == "" {
			return nil, fmt.Errorf("event at index %d has empty signature", i)
		}
	}

	apiURL := strings.Replace(config.RelayURL, "ws://", "http://", 1)
	apiURL = strings.Replace(apiURL, "wss://", "https://", 1)
	apiURL = apiURL + "/api/quotes/batch"

	logger.Info("Publishing batch of events to relay", "url", apiURL, "count", len(events))

	batchReq := BatchPublishRequest{Events: events}
	reqJSON, err := json.Marshal(batchReq)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "POST",
		Url:    apiURL,
		Body:   reqJSON,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}).Await()

	if err != nil {
		logger.Error("Failed to publish batch to relay", "error", err)
		return nil, fmt.Errorf("relay batch publish failed: %w", err)
	}

	if resp.StatusCode != 200 && resp.StatusCode != 201 {
		logger.Error("Non-success status from relay batch", "status", resp.StatusCode, "body", string(resp.Body))
		return &BatchPublishResponse{
			Success:   false,
			Published: 0,
			Failed:    len(events),
			Message:   fmt.Sprintf("relay returned status %d: %s", resp.StatusCode, string(resp.Body)),
		}, nil
	}

	var batchResp BatchPublishResponse
	if err := json.Unmarshal(resp.Body, &batchResp); err != nil {
		logger.Warn("Could not parse batch response, assuming success", "error", err)
		return &BatchPublishResponse{
			Success:   true,
			Published: len(events),
			Failed:    0,
			Message:   "Batch published (response not parsed)",
		}, nil
	}

	logger.Info("Successfully published batch to relay", "published", batchResp.Published, "failed", batchResp.Failed)

	return &batchResp, nil
}

// --- Price Adjustment Control Event ---

// fetchAdjustmentControl fetches the current price adjustment control event from the relay.
// Returns nil (no error) if no control event exists — means no adjustment is active.
// Uses /api/query (NIP-01 filter) instead of /api/quotes/batch/fetch which has a d-tag filter bug.
//
// SECURITY (C2): authorPubkey MUST be the oracle's own Schnorr pubkey. The
// adjustment control is published by this workflow signing with its own key
// (see publishAdjustmentControl), so a legitimate control event always has
// PubKey == oracle pubkey. We pin the relay query to that author AND, defense
// in depth against a malicious/buggy relay, re-check event.PubKey and verify
// the event's Schnorr signature before trusting its content. Without this, any
// party able to publish a kind-30078 event to the relay could move the oracle's
// published price (which drives liquidations). An empty authorPubkey disables
// the adjustment read entirely (fail closed) rather than trusting an unsigned event.
func fetchAdjustmentControl(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, authorPubkey string) (*PriceAdjustmentControl, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if authorPubkey == "" {
		// Fail closed: never read an adjustment control without an author to pin.
		logger.Warn("No author pubkey to pin adjustment control; ignoring adjustment")
		return nil, nil
	}

	// Use /api/query endpoint with NIP-01 filter (batch/fetch has a d-tag filter bug)
	apiURL := relayBaseAPIURL(config.RelayURL) + "/api/query"

	logger.Debug("Fetching price adjustment control event", "url", apiURL)

	// NIP-01 filter: kind 30078 with d-tag matching the adjustment control tag,
	// pinned to the oracle's own pubkey as author.
	filter := map[string]interface{}{
		"kinds":   []int{30078},
		"#d":      []string{AdjustmentControlDTag},
		"authors": []string{authorPubkey},
		"limit":   1,
	}
	reqJSON, err := json.Marshal(filter)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal control query request: %w", err)
	}

	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "POST",
		Url:    apiURL,
		Body:   reqJSON,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
	}).Await()

	if err != nil {
		logger.Warn("Failed to fetch adjustment control event", "error", err)
		return nil, nil // Non-fatal: no adjustment
	}

	if resp.StatusCode != 200 {
		logger.Warn("Non-200 fetching adjustment control", "status", resp.StatusCode)
		return nil, nil // Non-fatal: no adjustment
	}

	// /api/query returns []NostrEvent directly
	var events []NostrEvent
	if err := json.Unmarshal(resp.Body, &events); err != nil {
		logger.Warn("Failed to parse adjustment control response", "error", err)
		return nil, nil
	}

	if len(events) == 0 {
		logger.Debug("No adjustment control event found")
		return nil, nil
	}

	// SECURITY (C2): defense in depth against a malicious/buggy relay that
	// ignores the authors filter — re-check the author and verify the Schnorr
	// signature before trusting the event content.
	event := events[0]
	if event.PubKey != authorPubkey {
		logger.Warn("Ignoring adjustment control from unexpected author", "author", event.PubKey)
		return nil, nil
	}
	if err := verifyNostrEvent(&event); err != nil {
		logger.Warn("Ignoring adjustment control with invalid signature", "error", err)
		return nil, nil
	}

	var control PriceAdjustmentControl
	if err := json.Unmarshal([]byte(event.Content), &control); err != nil {
		logger.Warn("Failed to parse adjustment control content", "error", err)
		return nil, nil
	}
	logger.Info("Found adjustment control event", "pct", control.Pct, "expiresAt", control.ExpiresAt, "setAt", control.SetAt)
	return &control, nil
}

// publishAdjustmentControl publishes a price adjustment control event to the relay.
// This is a NIP-33 replaceable event keyed by the AdjustmentControlDTag.
func publishAdjustmentControl(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, keys *KeyDerivation, control *PriceAdjustmentControl, currentStamp int64) (*RelayResponse, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if keys == nil {
		return nil, fmt.Errorf("keys cannot be nil")
	}
	if control == nil {
		return nil, fmt.Errorf("control cannot be nil")
	}

	// Marshal control data as event content
	contentJSON, err := json.Marshal(control)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal control event: %w", err)
	}

	// Create NIP-33 replaceable event with the control d-tag
	event := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: currentStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", AdjustmentControlDTag},
			{"domain", "dev-control"},
		},
		Content: string(contentJSON),
	}

	// Sign the event
	if err := signNostrEvent(event, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign control event: %w", err)
	}

	logger.Info("Publishing adjustment control event", "pct", control.Pct, "expiresAt", control.ExpiresAt)

	return publishEvent(config, logger, sendRequester, event)
}
