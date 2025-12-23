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
