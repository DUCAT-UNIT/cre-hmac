package wasmtest

import (
	"errors"
	"testing"

	"ducat/shared"
)

// TestMockRelayClient_PublishEvent tests the mock relay publish behavior
func TestMockRelayClient_PublishEvent(t *testing.T) {
	tests := []struct {
		name        string
		setupError  error
		wantSuccess bool
		wantErr     bool
	}{
		{
			name:        "successful publish",
			setupError:  nil,
			wantSuccess: true,
			wantErr:     false,
		},
		{
			name:        "relay error",
			setupError:  errors.New("connection refused"),
			wantSuccess: false,
			wantErr:     true,
		},
		{
			name:        "relay timeout",
			setupError:  errors.New("timeout waiting for response"),
			wantSuccess: false,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewMockRelayClient()
			client.PublishError = tt.setupError

			event := &shared.NostrEvent{
				ID:        "test-event-id",
				PubKey:    "test-pubkey",
				CreatedAt: 1700000000,
				Kind:      30078,
				Tags:      [][]string{{"d", "test-dtag"}},
				Content:   "{}",
				Sig:       "test-sig",
			}

			resp, err := client.PublishEvent(event)

			if (err != nil) != tt.wantErr {
				t.Errorf("PublishEvent() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if resp.Success != tt.wantSuccess {
				t.Errorf("PublishEvent() success = %v, want %v", resp.Success, tt.wantSuccess)
			}

			if tt.wantSuccess && len(client.PublishedEvents) != 1 {
				t.Errorf("Expected 1 published event, got %d", len(client.PublishedEvents))
			}
		})
	}
}

// TestMockRelayClient_FetchByDTag tests the mock relay fetch behavior
func TestMockRelayClient_FetchByDTag(t *testing.T) {
	tests := []struct {
		name       string
		setupError error
		storeEvent bool
		dTag       string
		wantErr    bool
	}{
		{
			name:       "successful fetch",
			setupError: nil,
			storeEvent: true,
			dTag:       "existing-dtag",
			wantErr:    false,
		},
		{
			name:       "event not found",
			setupError: nil,
			storeEvent: false,
			dTag:       "nonexistent-dtag",
			wantErr:    true,
		},
		{
			name:       "relay fetch error",
			setupError: errors.New("relay unavailable"),
			storeEvent: true,
			dTag:       "existing-dtag",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewMockRelayClient()
			client.FetchError = tt.setupError

			if tt.storeEvent {
				event := &shared.NostrEvent{
					ID:        "stored-event-id",
					PubKey:    "test-pubkey",
					CreatedAt: 1700000000,
					Kind:      30078,
					Tags:      [][]string{{"d", "existing-dtag"}},
					Content:   "{}",
					Sig:       "test-sig",
				}
				client.StoredEvents["existing-dtag"] = event
			}

			result, err := client.FetchByDTag(tt.dTag)

			if (err != nil) != tt.wantErr {
				t.Errorf("FetchByDTag() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && result == nil {
				t.Error("FetchByDTag() returned nil result without error")
			}
		})
	}
}

// TestMockRelayClient_BatchPublish tests batch publish simulation
func TestMockRelayClient_BatchPublish(t *testing.T) {
	client := NewMockRelayClient()

	events := make([]*shared.NostrEvent, 10)
	for i := 0; i < 10; i++ {
		events[i] = &shared.NostrEvent{
			ID:        "batch-event-" + string(rune('0'+i)),
			PubKey:    "test-pubkey",
			CreatedAt: 1700000000,
			Kind:      30078,
			Tags:      [][]string{{"d", "batch-dtag-" + string(rune('0'+i))}},
			Content:   "{}",
			Sig:       "test-sig",
		}
	}

	// Simulate batch publish
	for _, event := range events {
		_, err := client.PublishEvent(event)
		if err != nil {
			t.Fatalf("Batch publish failed: %v", err)
		}
	}

	if len(client.PublishedEvents) != 10 {
		t.Errorf("Expected 10 published events, got %d", len(client.PublishedEvents))
	}

	if len(client.StoredEvents) != 10 {
		t.Errorf("Expected 10 stored events, got %d", len(client.StoredEvents))
	}
}

// TestMockRelayClient_PublishThenFetch tests publish-fetch round trip
func TestMockRelayClient_PublishThenFetch(t *testing.T) {
	client := NewMockRelayClient()

	dTag := "round-trip-test"
	originalEvent := &shared.NostrEvent{
		ID:        "original-id",
		PubKey:    "test-pubkey",
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", dTag}},
		Content:   `{"test": "data"}`,
		Sig:       "test-sig",
	}

	// Publish
	resp, err := client.PublishEvent(originalEvent)
	if err != nil {
		t.Fatalf("Publish failed: %v", err)
	}
	if !resp.Success {
		t.Fatalf("Publish not successful: %s", resp.Message)
	}

	// Fetch
	fetchedEvent, err := client.FetchByDTag(dTag)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	// Verify round trip
	if fetchedEvent.ID != originalEvent.ID {
		t.Errorf("ID mismatch: got %s, want %s", fetchedEvent.ID, originalEvent.ID)
	}
	if fetchedEvent.Content != originalEvent.Content {
		t.Errorf("Content mismatch: got %s, want %s", fetchedEvent.Content, originalEvent.Content)
	}
}

// TestMockRelayClient_ErrorRecovery tests error then recovery scenario
func TestMockRelayClient_ErrorRecovery(t *testing.T) {
	client := NewMockRelayClient()

	event := &shared.NostrEvent{
		ID:        "recovery-test",
		PubKey:    "test-pubkey",
		CreatedAt: 1700000000,
		Kind:      30078,
		Tags:      [][]string{{"d", "recovery-dtag"}},
		Content:   "{}",
		Sig:       "test-sig",
	}

	// First attempt fails
	client.PublishError = errors.New("temporary failure")
	resp1, _ := client.PublishEvent(event)
	if resp1.Success {
		t.Error("Expected first publish to fail")
	}

	// Second attempt succeeds (error cleared)
	client.PublishError = nil
	resp2, err := client.PublishEvent(event)
	if err != nil {
		t.Errorf("Second publish should succeed: %v", err)
	}
	if !resp2.Success {
		t.Error("Expected second publish to succeed")
	}
}

// TestMockRelayClient_ConcurrentAccess tests thread safety
func TestMockRelayClient_ConcurrentAccess(t *testing.T) {
	client := NewMockRelayClient()

	done := make(chan bool, 100)

	// Concurrent publishes
	for i := 0; i < 50; i++ {
		go func(id int) {
			event := &shared.NostrEvent{
				ID:        "concurrent-" + string(rune('0'+id%10)),
				PubKey:    "test-pubkey",
				CreatedAt: 1700000000,
				Kind:      30078,
				Tags:      [][]string{{"d", "concurrent-dtag-" + string(rune('0'+id%10))}},
				Content:   "{}",
				Sig:       "test-sig",
			}
			client.PublishEvent(event)
			done <- true
		}(i)
	}

	// Concurrent fetches
	for i := 0; i < 50; i++ {
		go func(id int) {
			client.FetchByDTag("concurrent-dtag-" + string(rune('0'+id%10)))
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 100; i++ {
		<-done
	}

	// Should not panic and should have some published events
	if len(client.PublishedEvents) == 0 {
		t.Error("Expected some published events from concurrent access")
	}
}

// TestMockRelayClient_GetLatestQuoteTimestamp tests rate limiting timestamp behavior
func TestMockRelayClient_GetLatestQuoteTimestamp(t *testing.T) {
	tests := []struct {
		name           string
		setupTimestamp int64
		setupError     error
		storedEvents   []*shared.NostrEvent
		oraclePubkey   string
		wantTimestamp  int64
		wantErr        bool
	}{
		{
			name:           "explicit timestamp set",
			setupTimestamp: 1700000100,
			oraclePubkey:   "test-pubkey",
			wantTimestamp:  1700000100,
			wantErr:        false,
		},
		{
			name:           "no quotes exist",
			setupTimestamp: 0,
			oraclePubkey:   "test-pubkey",
			wantTimestamp:  0,
			wantErr:        false,
		},
		{
			name:       "find from stored events",
			oraclePubkey: "test-pubkey",
			storedEvents: []*shared.NostrEvent{
				{ID: "event1", PubKey: "test-pubkey", CreatedAt: 1700000050, Tags: [][]string{{"d", "hash1"}}},
				{ID: "event2", PubKey: "test-pubkey", CreatedAt: 1700000100, Tags: [][]string{{"d", "hash2"}}},
				{ID: "event3", PubKey: "other-pubkey", CreatedAt: 1700000200, Tags: [][]string{{"d", "hash3"}}},
			},
			wantTimestamp: 1700000100, // Most recent from test-pubkey
			wantErr:       false,
		},
		{
			name:         "relay error",
			setupError:   errors.New("relay unavailable"),
			oraclePubkey: "test-pubkey",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewMockRelayClient()
			client.LatestQuoteTimestamp = tt.setupTimestamp
			client.LatestTimestampError = tt.setupError

			// Add stored events if provided
			for _, event := range tt.storedEvents {
				for _, tag := range event.Tags {
					if len(tag) >= 2 && tag[0] == "d" {
						client.StoredEvents[tag[1]] = event
						break
					}
				}
			}

			timestamp, err := client.GetLatestQuoteTimestamp(tt.oraclePubkey)

			if (err != nil) != tt.wantErr {
				t.Errorf("GetLatestQuoteTimestamp() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if !tt.wantErr && timestamp != tt.wantTimestamp {
				t.Errorf("GetLatestQuoteTimestamp() = %d, want %d", timestamp, tt.wantTimestamp)
			}
		})
	}
}

// TestMockLogger tests all MockLogger methods
func TestMockLogger(t *testing.T) {
	logger := NewMockLogger()

	// Test Info
	logger.Info("test info message", "key1", "value1")
	if len(logger.Messages) != 1 {
		t.Errorf("Expected 1 message after Info, got %d", len(logger.Messages))
	}
	if logger.Messages[0].Level != "INFO" {
		t.Errorf("Expected INFO level, got %s", logger.Messages[0].Level)
	}
	if logger.Messages[0].Message != "test info message" {
		t.Errorf("Expected 'test info message', got %s", logger.Messages[0].Message)
	}

	// Test Error
	logger.Error("test error message", "error", "some error")
	if len(logger.Messages) != 2 {
		t.Errorf("Expected 2 messages after Error, got %d", len(logger.Messages))
	}
	if logger.Messages[1].Level != "ERROR" {
		t.Errorf("Expected ERROR level, got %s", logger.Messages[1].Level)
	}
	if logger.Messages[1].Message != "test error message" {
		t.Errorf("Expected 'test error message', got %s", logger.Messages[1].Message)
	}

	// Test Warn
	logger.Warn("test warning message", "warning", "some warning")
	if len(logger.Messages) != 3 {
		t.Errorf("Expected 3 messages after Warn, got %d", len(logger.Messages))
	}
	if logger.Messages[2].Level != "WARN" {
		t.Errorf("Expected WARN level, got %s", logger.Messages[2].Level)
	}
	if logger.Messages[2].Message != "test warning message" {
		t.Errorf("Expected 'test warning message', got %s", logger.Messages[2].Message)
	}
}

// TestMockWebhookClient_SendCallback tests the SendCallback method
func TestMockWebhookClient_SendCallback(t *testing.T) {
	tests := []struct {
		name       string
		setupError error
		url        string
		payload    map[string]interface{}
		wantErr    bool
		wantCount  int
	}{
		{
			name:       "successful callback",
			setupError: nil,
			url:        "https://example.com/webhook",
			payload:    map[string]interface{}{"event": "test", "data": "value"},
			wantErr:    false,
			wantCount:  1,
		},
		{
			name:       "callback error",
			setupError: errors.New("connection refused"),
			url:        "https://example.com/webhook",
			payload:    map[string]interface{}{"event": "test"},
			wantErr:    true,
			wantCount:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := NewMockWebhookClient()
			client.Error = tt.setupError

			err := client.SendCallback(tt.url, tt.payload)

			if (err != nil) != tt.wantErr {
				t.Errorf("SendCallback() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if len(client.Callbacks) != tt.wantCount {
				t.Errorf("Callbacks count = %d, want %d", len(client.Callbacks), tt.wantCount)
			}

			if tt.wantCount > 0 {
				if client.Callbacks[0].URL != tt.url {
					t.Errorf("Callback URL = %q, want %q", client.Callbacks[0].URL, tt.url)
				}
			}
		})
	}
}

// TestMockWebhookClient_MultipleCallbacks tests multiple callbacks
func TestMockWebhookClient_MultipleCallbacks(t *testing.T) {
	client := NewMockWebhookClient()

	// Send multiple callbacks
	for i := 0; i < 5; i++ {
		url := "https://example.com/webhook"
		payload := map[string]interface{}{"index": i}
		err := client.SendCallback(url, payload)
		if err != nil {
			t.Fatalf("SendCallback failed: %v", err)
		}
	}

	if len(client.Callbacks) != 5 {
		t.Errorf("Expected 5 callbacks, got %d", len(client.Callbacks))
	}
}
