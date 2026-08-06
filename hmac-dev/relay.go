//go:build wasip1

package main

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"ducat/shared"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"google.golang.org/protobuf/types/known/durationpb"
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

// fetchEventByDTag retrieves a single quote by lookup tag from the relay.
//
// SECURITY (M7): oraclePubkey MUST be the oracle's own Schnorr pubkey. Quotes
// are published by this workflow signing with its own key, so a legitimate quote
// event always has PubKey == oraclePubkey. We pin the relay /api/query filter to
// that author AND, defense in depth against a malicious/buggy relay that ignores
// the filter, re-check event.PubKey before (alongside) the existing signature
// verification. An empty oraclePubkey is a programming error (callers must always
// pass keys.SchnorrPubkey) and is rejected fail-closed.
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
		"kinds":   []int{30000, 1000},
		"#h":      []string{dTag},
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
	// Do not rely on the relay to honor the filter. A malicious or buggy relay
	// can replay a different, validly signed oracle event unless kind and lookup
	// tag are rebound locally to this request.
	if event.Kind != NostrEventKindContract && event.Kind != NostrEventKindBreach {
		errMsg := fmt.Sprintf("quote has unexpected kind %d", event.Kind)
		result.Error = &errMsg
		return result, nil
	}
	if !event.HasTagValue("h", dTag) {
		errMsg := fmt.Sprintf("quote is not bound to requested lookup hash %q", dTag)
		result.Error = &errMsg
		return result, nil
	}

	result.Event = event
	return result, nil
}

// BatchPublishResponse is the response from batch publishing
type BatchPublishResponse struct {
	Success   bool   `json:"success" consensus_aggregation:"identical"`
	Published int    `json:"published" consensus_aggregation:"median"`
	Failed    int    `json:"failed" consensus_aggregation:"median"`
	Message   string `json:"message" consensus_aggregation:"identical"`
}

// MaxEventsPerBatch is the maximum number of events per HTTP request.
// Keep each gzipped chunk under the CRE platform cap of 200 KB per outbound
// HTTP body. Active quote payloads must keep thold_key:null for client schema
// compatibility, so 130 events is the safe chunk size under the CRE envelope.
const MaxEventsPerBatch = 130

// CRE's default HTTP timeout is 5s, which is too tight for large ladder chunks
// routed through the DON HTTP gateway. Keep the timeout explicit on batch posts
// so the full-size worker can publish larger gzipped chunks reliably.
const BatchPublishTimeout = 10 * time.Second

func gzipPayload(payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestSpeed)
	if err != nil {
		return nil, err
	}
	if _, err := zw.Write(payload); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

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

	reqJSON, err := json.Marshal(events)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch request: %w", err)
	}

	reqBody, err := gzipPayload(reqJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to gzip batch request: %w", err)
	}
	logger.Info("Compressed batch payload", "count", len(events), "rawBytes", len(reqJSON), "gzipBytes", len(reqBody))

	resp, err := sendRequester.SendRequest(&http.Request{
		Method:  "POST",
		Url:     apiURL,
		Body:    reqBody,
		Timeout: durationpb.New(BatchPublishTimeout),
		Headers: map[string]string{
			"Content-Type":              "application/json",
			"Content-Encoding":          "gzip",
			"X-Uncompressed-Body-Bytes": fmt.Sprintf("%d", len(reqJSON)),
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
		return nil, fmt.Errorf("could not parse successful relay batch response: %w", err)
	}
	if err := shared.ValidateBatchPublishResult(batchResp.Success, batchResp.Published, batchResp.Failed, len(events)); err != nil {
		return nil, fmt.Errorf("invalid relay batch response: %w", err)
	}

	logger.Info("Successfully published batch to relay", "published", batchResp.Published, "failed", batchResp.Failed)

	return &batchResp, nil
}

// fetchAdjustmentControl fetches the price adjustment control event from the relay.
// When authorPubkey is set, only control events signed by that Nostr pubkey are accepted.
func fetchAdjustmentControl(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, authorPubkey string) (*PriceAdjustmentControl, error) {
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if authorPubkey == "" {
		logger.Warn("No author pubkey to pin adjustment control; ignoring adjustment")
		return nil, nil
	}

	apiURL := relayBaseAPIURL(config.RelayURL) + "/api/query"

	filter := map[string]interface{}{
		"kinds": []int{30078},
		"#d":    []string{AdjustmentControlDTag},
		"limit": 1,
	}
	filter["authors"] = []string{authorPubkey}
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
		return nil, nil
	}

	if resp.StatusCode != 200 {
		logger.Warn("Non-200 fetching adjustment control", "status", resp.StatusCode)
		return nil, nil
	}

	var events []NostrEvent
	if err := json.Unmarshal(resp.Body, &events); err != nil {
		logger.Warn("Failed to parse adjustment control response", "error", err)
		return nil, nil
	}

	if len(events) == 0 {
		logger.Debug("No adjustment control event found")
		return nil, nil
	}

	event := events[0]
	if event.PubKey != authorPubkey {
		logger.Warn("Ignoring adjustment control from unexpected author", "author", event.PubKey)
		return nil, nil
	}
	if err := verifyNostrEvent(&event); err != nil {
		logger.Warn("Ignoring adjustment control with invalid signature", "error", err)
		return nil, nil
	}
	if event.Kind != NostrEventKindThresholdCommitment || !event.HasTagValue("d", AdjustmentControlDTag) {
		logger.Warn("Ignoring adjustment control that does not match requested kind/tag", "kind", event.Kind)
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

// publishAdjustmentControl publishes a NIP-33 replaceable control event keyed
// by AdjustmentControlDTag. The unified cycle reads this event before creating
// the dev price snapshot and ladder.
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

	contentJSON, err := json.Marshal(control)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal control event: %w", err)
	}

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

	if err := signNostrEvent(event, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign control event: %w", err)
	}

	logger.Info("Publishing adjustment control event", "pct", control.Pct, "expiresAt", control.ExpiresAt)
	return publishEvent(config, logger, sendRequester, event)
}
