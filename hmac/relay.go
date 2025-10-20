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
// Replaceable by d tag (threshold hash)
func publishEvent(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, event *NostrEvent) (*RelayResponse, error) {
	// Validate inputs
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

	// Convert WebSocket URL to HTTP API URL
	// ws://localhost:7000 -> http://localhost:7000
	// wss://relay.example.com -> https://relay.example.com
	apiURL := strings.Replace(config.RelayURL, "ws://", "http://", 1)
	apiURL = strings.Replace(apiURL, "wss://", "https://", 1)
	apiURL = apiURL + "/api/quotes"

	logger.Info("Publishing event to relay", "url", apiURL, "eventId", event.ID)

	// Marshal event to JSON
	eventJSON, err := json.Marshal(event)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal event: %w", err)
	}

	// POST to relay API endpoint
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

	// Accept both 200 OK and 201 Created as success
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

// fetchEvent retrieves quote by event ID and verifies signature
func fetchEvent(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, eventID string) (*NostrEvent, error) {
	// Validate inputs
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if eventID == "" {
		return nil, fmt.Errorf("event ID cannot be empty")
	}

	// Convert WebSocket URL to HTTP API URL
	apiURL := strings.Replace(config.RelayURL, "ws://", "http://", 1)
	apiURL = strings.Replace(apiURL, "wss://", "https://", 1)
	apiURL = fmt.Sprintf("%s/api/quotes/%s", apiURL, eventID)

	logger.Info("Fetching event from relay", "url", apiURL, "eventId", eventID)

	// GET from relay API
	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "GET",
		Url:    apiURL,
	}).Await()

	if err != nil {
		logger.Error("Failed to fetch from relay", "error", err)
		return nil, fmt.Errorf("relay fetch failed: %w", err)
	}

	// Handle 404 explicitly - quote not found
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("event not found: %s", eventID)
	}

	// Validate successful response
	if resp.StatusCode != 200 {
		logger.Error("Non-200 status from relay", "status", resp.StatusCode, "body", string(resp.Body))
		return nil, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	// Parse event JSON
	var event NostrEvent
	if err := json.Unmarshal(resp.Body, &event); err != nil {
		logger.Error("Failed to parse event from relay", "error", err)
		return nil, fmt.Errorf("failed to parse event: %w", err)
	}

	// Verify event signature to prevent tampering
	// Uses constant-time comparison internally
	if err := verifyNostrEvent(&event); err != nil {
		logger.Error("Event signature verification failed", "error", err, "eventId", eventID)
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	logger.Info("Successfully fetched and verified event", "eventId", event.ID)

	return &event, nil
}

// fetchEventByDTag retrieves quote by threshold hash (d tag)
// Primary method for checking breach status
func fetchEventByDTag(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, dTag string) (*NostrEvent, error) {
	// Validate inputs
	if config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if dTag == "" {
		return nil, fmt.Errorf("d tag cannot be empty")
	}

	// Validate d tag format (should be 40 hex characters for hash160)
	if len(dTag) != 40 {
		return nil, fmt.Errorf("invalid d tag length: expected 40 hex chars, got %d", len(dTag))
	}

	// Convert WebSocket URL to HTTP API URL
	apiURL := strings.Replace(config.RelayURL, "ws://", "http://", 1)
	apiURL = strings.Replace(apiURL, "wss://", "https://", 1)
	apiURL = fmt.Sprintf("%s/api/quotes?d=%s", apiURL, dTag)

	logger.Info("Fetching event by d tag from relay", "url", apiURL, "dTag", dTag)

	// GET from relay API
	resp, err := sendRequester.SendRequest(&http.Request{
		Method: "GET",
		Url:    apiURL,
	}).Await()

	if err != nil {
		logger.Error("Failed to fetch from relay", "error", err)
		return nil, fmt.Errorf("relay fetch failed: %w", err)
	}

	// Handle 404 explicitly - no quote exists for this threshold
	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("event not found for d tag: %s", dTag)
	}

	// Validate successful response
	if resp.StatusCode != 200 {
		logger.Error("Non-200 status from relay", "status", resp.StatusCode, "body", string(resp.Body))
		return nil, fmt.Errorf("relay returned status %d: %s", resp.StatusCode, string(resp.Body))
	}

	// Parse event JSON
	var event NostrEvent
	if err := json.Unmarshal(resp.Body, &event); err != nil {
		logger.Error("Failed to parse event from relay", "error", err)
		return nil, fmt.Errorf("failed to parse event: %w", err)
	}

	// Verify event signature to prevent tampering
	// Uses constant-time comparison internally
	if err := verifyNostrEvent(&event); err != nil {
		logger.Error("Event signature verification failed", "error", err, "dTag", dTag)
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	logger.Info("Successfully fetched and verified event by d tag", "eventId", event.ID, "dTag", dTag)

	return &event, nil
}
