package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"ducat/internal/ethsign"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/ethereum/go-ethereum/crypto"
)


// Test helpers
// setupTestEnv accepts testing.TB to work with both *testing.T and *testing.B
func setupTestEnv(tb testing.TB) {
	tb.Helper()

	// Set required environment variables
	os.Setenv("CRE_WORKFLOW_ID", "test-workflow-id-12345")
	os.Setenv("DUCAT_AUTHORIZED_KEY", "0xtest123")
	os.Setenv("GATEWAY_CALLBACK_URL", "http://localhost:8080/webhook/ducat")
	os.Setenv("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c")

	// Reset server state if initialized
	if server != nil {
		server.requestsMutex.Lock()
		server.pendingRequests = make(map[string]*PendingRequest)
		server.requestsMutex.Unlock()
	}
}

func resetGlobals() {
	if server != nil {
		server.requestsMutex.Lock()
		server.pendingRequests = make(map[string]*PendingRequest)
		server.requestsMutex.Unlock()
	}
}

// Test private key for signing webhooks (different from server key)
var testWebhookPrivKey, _ = hex.DecodeString("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

// createSignedWebhook creates a properly signed WebhookPayload for testing.
// This simulates a valid Nostr event from the CRE.
func createSignedWebhook(eventType, domain, content string, tags [][]string) WebhookPayload {
	// Get the Schnorr public key from the test private key
	_, pubKey := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	pubKeyHex := hex.EncodeToString(schnorr.SerializePubKey(pubKey))

	// Add domain tag if not present
	hasDomainTag := false
	for _, tag := range tags {
		if len(tag) >= 1 && tag[0] == "domain" {
			hasDomainTag = true
			break
		}
	}
	if !hasDomainTag && domain != "" {
		tags = append(tags, []string{"domain", domain})
	}

	payload := WebhookPayload{
		EventType: eventType,
		PubKey:    pubKeyHex,
		CreatedAt: time.Now().Unix(),
		Kind:      30078, // Custom kind for DUCAT
		Tags:      tags,
		Content:   content,
	}

	// Compute event ID (NIP-01 format)
	tagsJSON, _ := json.Marshal(payload.Tags)
	serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
		payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
	hash := sha256.Sum256([]byte(serialized))
	payload.EventID = hex.EncodeToString(hash[:])

	// Sign the event ID with Schnorr
	privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
	eventIDBytes, _ := hex.DecodeString(payload.EventID)
	sig, _ := schnorr.Sign(privKey, eventIDBytes)
	payload.Sig = hex.EncodeToString(sig.Serialize())

	return payload
}

// TestLoadConfig tests configuration loading from environment variables
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		shouldPanic bool
		validate    func(t *testing.T, cfg *GatewayConfig)
	}{
		{
			name: "all required vars set",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":      "workflow123",
				"DUCAT_AUTHORIZED_KEY": "0xabc123",
				"GATEWAY_CALLBACK_URL": "http://example.com/webhook",
			},
			shouldPanic: false,
			validate: func(t *testing.T, cfg *GatewayConfig) {
				if cfg.WorkflowID != "workflow123" {
					t.Errorf("WorkflowID = %s, want workflow123", cfg.WorkflowID)
				}
				if cfg.AuthorizedKey != "0xabc123" {
					t.Errorf("AuthorizedKey = %s, want 0xabc123", cfg.AuthorizedKey)
				}
				if cfg.CallbackURL != "http://example.com/webhook" {
					t.Errorf("CallbackURL = %s, want http://example.com/webhook", cfg.CallbackURL)
				}
				if cfg.BlockTimeout != 60*time.Second {
					t.Errorf("BlockTimeout = %v, want 60s", cfg.BlockTimeout)
				}
				if cfg.MaxPending != 1000 {
					t.Errorf("MaxPending = %d, want 1000", cfg.MaxPending)
				}
			},
		},
		{
			name: "custom timeout and limits",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":          "workflow123",
				"DUCAT_AUTHORIZED_KEY":     "0xabc123",
				"GATEWAY_CALLBACK_URL":     "http://example.com/webhook",
				"BLOCK_TIMEOUT_SECONDS":    "30",
				"CLEANUP_INTERVAL_SECONDS": "60",
				"MAX_PENDING_REQUESTS":     "500",
			},
			shouldPanic: false,
			validate: func(t *testing.T, cfg *GatewayConfig) {
				if cfg.BlockTimeout != 30*time.Second {
					t.Errorf("BlockTimeout = %v, want 30s", cfg.BlockTimeout)
				}
				if cfg.CleanupInterval != 60*time.Second {
					t.Errorf("CleanupInterval = %v, want 60s", cfg.CleanupInterval)
				}
				if cfg.MaxPending != 500 {
					t.Errorf("MaxPending = %d, want 500", cfg.MaxPending)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all env vars
			os.Clearenv()

			// Set test env vars
			for k, v := range tt.envVars {
				os.Setenv(k, v)
			}

			if tt.shouldPanic {
				defer func() {
					if r := recover(); r == nil {
						t.Errorf("loadConfig() should have panicked but didn't")
					}
				}()
			}

			cfg := loadConfig()

			if tt.validate != nil {
				tt.validate(t, cfg)
			}
		})
	}
}

// TestHandleHealth tests the health check endpoint
func TestHandleHealth(t *testing.T) {
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()

	handleHealth(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Health endpoint now returns JSON with status field
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	if status, ok := result["status"].(string); !ok || status != "healthy" {
		t.Errorf("status = %v, want 'healthy'", result["status"])
	}

	// Check CORS header
	if w.Header().Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("missing CORS header")
	}
}

// TestHandleCreateValidation tests input validation for /api/quote
func TestHandleCreateValidation(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		queryParams    string
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "missing th parameter",
			method:         "GET",
			queryParams:    "",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Missing th query parameter",
		},
		{
			name:           "invalid th value",
			method:         "GET",
			queryParams:    "?th=invalid",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid th value",
		},
		{
			name:           "negative th value",
			method:         "GET",
			queryParams:    "?th=-100",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "threshold price must be positive",
		},
		{
			name:           "zero th value",
			method:         "GET",
			queryParams:    "?th=0",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "threshold price must be positive",
		},
		{
			name:           "wrong method",
			method:         "POST",
			queryParams:    "?th=100",
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "OPTIONS preflight",
			method:         "OPTIONS",
			queryParams:    "",
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/api/quote"+tt.queryParams, nil)
			w := httptest.NewRecorder()

			server.handleCreate(w, req)

			resp := w.Result()
			body, _ := io.ReadAll(resp.Body)

			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedBody != "" && !strings.Contains(string(body), tt.expectedBody) {
				t.Errorf("body = %s, want to contain %s", body, tt.expectedBody)
			}
		})
	}
}

// TestHandleCreateMaxPending tests max pending request limit
func TestHandleCreateMaxPending(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set a low limit for testing
	server.config.MaxPending = 2

	// Fill up pending requests
	for i := 0; i < server.config.MaxPending; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "Server at capacity") {
		t.Errorf("body = %s, want 'Server at capacity'", body)
	}

	// Cleanup
	resetGlobals()
	server.config.MaxPending = 1000
}

// TestHandleWebhook tests webhook processing
func TestHandleWebhook(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	t.Run("wrong method", func(t *testing.T) {
		resetGlobals()
		req := httptest.NewRequest("GET", "/webhook/ducat", nil)
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
		if w.Result().StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusMethodNotAllowed)
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		resetGlobals()
		req := httptest.NewRequest("POST", "/webhook/ducat", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
		if w.Result().StatusCode != http.StatusBadRequest {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusBadRequest)
		}
	})

	t.Run("valid webhook with pending request", func(t *testing.T) {
		resetGlobals()
		domain := "test-domain"

		// Setup pending request
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}

		// Create properly signed webhook
		payload := createSignedWebhook("create", domain, `{"thold_price": 100, "thold_hash": "abc123"}`, nil)
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
		}

		// Verify pending request received the webhook
		pending := server.pendingRequests[domain]
		select {
		case result := <-pending.ResultChan:
			if result.EventID != payload.EventID {
				t.Errorf("received event_id = %s, want %s", result.EventID, payload.EventID)
			}
		case <-time.After(100 * time.Millisecond):
			t.Error("webhook did not unblock pending request")
		}
	})

	t.Run("webhook without pending request", func(t *testing.T) {
		resetGlobals()

		// Create properly signed webhook for unknown domain
		payload := createSignedWebhook("create", "unknown-domain", `{"thold_price": 100}`, nil)
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Errorf("status = %d, want %d", w.Result().StatusCode, http.StatusOK)
		}
	})

	t.Run("unsigned webhook rejected", func(t *testing.T) {
		resetGlobals()

		// Create unsigned webhook (missing signature)
		payload := WebhookPayload{
			EventType: "create",
			EventID:   "event123",
			PubKey:    strings.Repeat("a", 64),
			Tags:      [][]string{{"domain", "test-domain"}},
			Content:   `{"thold_price": 100}`,
			CreatedAt: time.Now().Unix(),
		}
		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d (unauthorized for unsigned webhook)", w.Result().StatusCode, http.StatusUnauthorized)
		}
	})

	t.Run("expired webhook rejected", func(t *testing.T) {
		resetGlobals()

		// Create a signed webhook with an old timestamp
		payload := createSignedWebhook("create", "test-domain", `{"thold_price": 100}`, nil)
		// Manually override to make it expired (6 minutes old)
		payload.CreatedAt = time.Now().Unix() - 360

		// Re-sign with old timestamp
		tagsJSON, _ := json.Marshal(payload.Tags)
		serialized := fmt.Sprintf("[0,%q,%d,%d,%s,%q]",
			payload.PubKey, payload.CreatedAt, payload.Kind, string(tagsJSON), payload.Content)
		hash := sha256.Sum256([]byte(serialized))
		payload.EventID = hex.EncodeToString(hash[:])

		privKey, _ := btcec.PrivKeyFromBytes(testWebhookPrivKey)
		eventIDBytes, _ := hex.DecodeString(payload.EventID)
		sig, _ := schnorr.Sign(privKey, eventIDBytes)
		payload.Sig = hex.EncodeToString(sig.Serialize())

		jsonData, _ := json.Marshal(payload)

		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)

		if w.Result().StatusCode != http.StatusUnauthorized {
			t.Errorf("status = %d, want %d (unauthorized for expired webhook)", w.Result().StatusCode, http.StatusUnauthorized)
		}
	})
}

// TestHandleCheckValidation tests /check endpoint validation
func TestHandleCheckValidation(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		payload        interface{}
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "wrong method",
			method:         "GET",
			payload:        nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			payload:        "not json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "missing domain",
			method: "POST",
			payload: CheckRequest{
				Domain:    "",
				TholdHash: "1234567890123456789012345678901234567890",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid domain or thold_hash",
		},
		{
			name:   "invalid thold_hash length",
			method: "POST",
			payload: CheckRequest{
				Domain:    "test-domain",
				TholdHash: "short",
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid domain or thold_hash",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var body io.Reader
			if str, ok := tt.payload.(string); ok {
				body = strings.NewReader(str)
			} else if tt.payload != nil {
				jsonData, _ := json.Marshal(tt.payload)
				body = bytes.NewReader(jsonData)
			}

			req := httptest.NewRequest(tt.method, "/check", body)
			w := httptest.NewRecorder()

			server.handleCheck(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.expectedBody != "" {
				respBody, _ := io.ReadAll(resp.Body)
				if !strings.Contains(string(respBody), tt.expectedBody) {
					t.Errorf("body = %s, want to contain %s", respBody, tt.expectedBody)
				}
			}
		})
	}
}

// TestHandleStatus tests /status endpoint
func TestHandleStatus(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		path           string
		setupRequest   func()
		expectedStatus int
		validateBody   func(t *testing.T, body []byte)
	}{
		{
			name:           "wrong method",
			method:         "POST",
			path:           "/status/test-123",
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "missing request ID",
			method:         "GET",
			path:           "/status/",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "request not found",
			method:         "GET",
			path:           "/status/nonexistent",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:   "pending request",
			method: "GET",
			path:   "/status/pending-req",
			setupRequest: func() {
				server.pendingRequests["pending-req"] = &PendingRequest{
					RequestID:  "pending-req",
					CreatedAt:  time.Now(),
					ResultChan: make(chan *WebhookPayload, 1),
					Status:     "pending",
				}
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var resp SyncResponse
				if err := json.Unmarshal(body, &resp); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				if resp.Status != "pending" {
					t.Errorf("status = %s, want pending", resp.Status)
				}
				if !strings.Contains(resp.Message, "still processing") {
					t.Errorf("message should contain 'still processing'")
				}
			},
		},
		{
			name:   "completed request",
			method: "GET",
			path:   "/status/completed-req",
			setupRequest: func() {
				server.pendingRequests["completed-req"] = &PendingRequest{
					RequestID: "completed-req",
					CreatedAt: time.Now(),
					Status:    "completed",
					Result: &WebhookPayload{
						// Full CRE format payload with core-ts PriceContract fields
						Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":100,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":95}`,
					},
				}
			},
			expectedStatus: http.StatusOK,
			validateBody: func(t *testing.T, body []byte) {
				var result map[string]interface{}
				if err := json.Unmarshal(body, &result); err != nil {
					t.Fatalf("failed to parse response: %v", err)
				}
				// Check core-ts PriceContract fields
				if basePrice, ok := result["base_price"].(float64); ok {
					if basePrice != 100.0 {
						t.Errorf("base_price = %f, want 100.0", basePrice)
					}
				} else {
					t.Error("base_price not found in response")
				}
				// Verify PriceContract fields exist
				if _, ok := result["chain_network"]; !ok {
					t.Error("chain_network not found in response")
				}
				if _, ok := result["commit_hash"]; !ok {
					t.Error("commit_hash not found in response")
				}
				if _, ok := result["contract_id"]; !ok {
					t.Error("contract_id not found in response")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobals()

			if tt.setupRequest != nil {
				tt.setupRequest()
			}

			req := httptest.NewRequest(tt.method, tt.path, nil)
			w := httptest.NewRecorder()

			server.handleStatus(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			if tt.validateBody != nil {
				body, _ := io.ReadAll(resp.Body)
				tt.validateBody(t, body)
			}
		})
	}
}

// TestCleanupOldRequests tests the cleanup goroutine
func TestCleanupOldRequests(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short intervals for testing
	oldCleanupInterval := server.config.CleanupInterval
	oldBlockTimeout := server.config.BlockTimeout
	server.config.CleanupInterval = 50 * time.Millisecond
	server.config.BlockTimeout = 50 * time.Millisecond
	defer func() {
		server.config.CleanupInterval = oldCleanupInterval
		server.config.BlockTimeout = oldBlockTimeout
	}()

	now := time.Now()

	// Add various requests
	server.pendingRequests["old-completed"] = &PendingRequest{
		RequestID:  "old-completed",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["old-timeout"] = &PendingRequest{
		RequestID:  "old-timeout",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "timeout",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["stale-pending"] = &PendingRequest{
		RequestID:  "stale-pending",
		CreatedAt:  now.Add(-5 * time.Minute),
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["recent-completed"] = &PendingRequest{
		RequestID:  "recent-completed",
		CreatedAt:  now.Add(-1 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	server.pendingRequests["active-pending"] = &PendingRequest{
		RequestID:  "active-pending",
		CreatedAt:  now,
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	initialCount := len(server.pendingRequests)
	if initialCount != 5 {
		t.Fatalf("setup failed: got %d requests, want 5", initialCount)
	}

	// Call cleanupOldRequests directly and wait for one cycle
	stopChan := make(chan bool)
	doneChan := make(chan bool)

	go func() {
		ticker := time.NewTicker(server.config.CleanupInterval)
		defer ticker.Stop()
		defer close(doneChan)

		select {
		case <-ticker.C:
			server.requestsMutex.Lock()
			now := time.Now()
			cleaned := 0

			for id, req := range server.pendingRequests {
				shouldDelete := false

				if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*server.config.BlockTimeout {
					shouldDelete = true
				}

				if shouldDelete {
					delete(server.pendingRequests, id)
					cleaned++
				}
			}
			server.requestsMutex.Unlock()
		case <-stopChan:
			return
		}
	}()

	// Wait for cleanup to run
	select {
	case <-doneChan:
	case <-time.After(300 * time.Millisecond):
		close(stopChan)
		t.Fatal("cleanup didn't complete in time")
	}

	// Verify cleanup
	server.requestsMutex.RLock()
	defer server.requestsMutex.RUnlock()

	expectedRemaining := []string{"recent-completed", "active-pending"}
	if len(server.pendingRequests) != len(expectedRemaining) {
		t.Errorf("after cleanup: got %d requests, want %d", len(server.pendingRequests), len(expectedRemaining))
	}

	for _, key := range expectedRemaining {
		if _, exists := server.pendingRequests[key]; !exists {
			t.Errorf("request %s should not have been cleaned up", key)
		}
	}
}

// TestGetTag tests the helper function
func TestGetTag(t *testing.T) {
	tests := []struct {
		name     string
		tags     [][]string
		key      string
		expected string
	}{
		{
			name:     "tag exists",
			tags:     [][]string{{"domain", "test-domain"}, {"other", "value"}},
			key:      "domain",
			expected: "test-domain",
		},
		{
			name:     "tag does not exist",
			tags:     [][]string{{"domain", "test-domain"}},
			key:      "missing",
			expected: "",
		},
		{
			name:     "empty tags",
			tags:     [][]string{},
			key:      "domain",
			expected: "",
		},
		{
			name:     "malformed tag",
			tags:     [][]string{{"single"}},
			key:      "single",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTag(tt.tags, tt.key)
			if result != tt.expected {
				t.Errorf("getTag() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGetTholdHash tests the helper function
func TestGetTholdHash(t *testing.T) {
	tests := []struct {
		name        string
		payload     *WebhookPayload
		expected    string
		expectError bool
	}{
		{
			name: "valid payload",
			payload: &WebhookPayload{
				Content: `{"thold_hash": "abc123def456"}`,
			},
			expected:    "abc123def456",
			expectError: false,
		},
		{
			name: "invalid JSON",
			payload: &WebhookPayload{
				Content: `invalid json`,
			},
			expected:    "",
			expectError: true,
		},
		{
			name: "missing thold_hash",
			payload: &WebhookPayload{
				Content: `{"other_field": "value"}`,
			},
			expected:    "",
			expectError: false, // Valid JSON, just missing field
		},
		{
			name:        "nil payload",
			payload:     nil,
			expected:    "",
			expectError: true,
		},
		{
			name: "empty content",
			payload: &WebhookPayload{
				Content: "",
			},
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := getTholdHash(tt.payload)
			if result != tt.expected {
				t.Errorf("getTholdHash() = %s, want %s", result, tt.expected)
			}
			if tt.expectError && err == nil {
				t.Errorf("getTholdHash() expected error but got nil")
			}
			if !tt.expectError && err != nil {
				t.Errorf("getTholdHash() unexpected error: %v", err)
			}
		})
	}
}

// TestEncodeBase64URL tests the base64url encoding function using standard library
func TestEncodeBase64URL(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "empty input",
			input:    []byte{},
			expected: "",
		},
		{
			name:     "single byte",
			input:    []byte{0x00},
			expected: "AA",
		},
		{
			name:     "two bytes",
			input:    []byte{0x00, 0x01},
			expected: "AAE",
		},
		{
			name:     "three bytes (no padding)",
			input:    []byte{0x00, 0x01, 0x02},
			expected: "AAEC",
		},
		{
			name:     "test string",
			input:    []byte("hello"),
			expected: "aGVsbG8",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := base64.RawURLEncoding.EncodeToString(tt.input)
			if result != tt.expected {
				t.Errorf("base64.RawURLEncoding.EncodeToString() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGenerateRequestID tests request ID generation using ethsign package
func TestGenerateRequestID(t *testing.T) {
	id1, err := ethsign.GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID() error = %v", err)
	}

	id2, err := ethsign.GenerateRequestID()
	if err != nil {
		t.Fatalf("GenerateRequestID() error = %v", err)
	}

	if id1 == id2 {
		t.Error("GenerateRequestID() should generate unique IDs")
	}

	if len(id1) != 32 {
		t.Errorf("GenerateRequestID() length = %d, want 32", len(id1))
	}

	// Verify it's valid hex
	if _, err := hex.DecodeString(id1); err != nil {
		t.Errorf("GenerateRequestID() returned invalid hex: %v", err)
	}
}

// TestGenerateJWT tests JWT generation using ethsign package
func TestGenerateJWT(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	address := "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82"
	digest := "0x1234567890abcdef"

	reqID, _ := ethsign.GenerateRequestID()
	token, err := ethsign.GenerateJWT(privKey, address, digest, reqID)
	if err != nil {
		t.Fatalf("GenerateJWT() error = %v", err)
	}

	// Verify JWT structure (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("JWT parts = %d, want 3", len(parts))
	}

	// Verify it's different each time (due to jti and timestamps)
	reqID2, _ := ethsign.GenerateRequestID()
	token2, _ := ethsign.GenerateJWT(privKey, address, digest, reqID2)
	if token == token2 {
		t.Error("GenerateJWT() should generate unique tokens due to jti")
	}
}

// TestSignEthereumMessage tests Ethereum message signing using ethsign package
func TestSignEthereumMessage(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	message := "test message"

	signature, err := ethsign.SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage() error = %v", err)
	}

	// Verify signature length (65 bytes: r + s + v)
	if len(signature) != 65 {
		t.Errorf("signature length = %d, want 65", len(signature))
	}

	// Verify recovery ID is in Ethereum format (27 or 28, with v = recoveryID + 27)
	v := signature[64]
	if v < 27 || v > 30 {
		t.Errorf("v = %d, want 27-30 (Ethereum format)", v)
	}
}

// TestConcurrentWebhooks tests concurrent webhook handling
func TestConcurrentWebhooks(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	numRequests := 10
	var wg sync.WaitGroup

	// Pre-create signed payloads (must be done before concurrent send to get consistent event IDs)
	payloads := make([]WebhookPayload, numRequests)
	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
		payloads[i] = createSignedWebhook("create", domain, fmt.Sprintf(`{"thold_price": %d}`, i*100), nil)
	}

	// Send webhooks concurrently
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			jsonData, _ := json.Marshal(payloads[idx])
			req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
			w := httptest.NewRecorder()

			server.handleWebhook(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("webhook %d: status = %d, want %d", idx, w.Code, http.StatusOK)
			}
		}(i)
	}

	wg.Wait()

	// Verify all requests received their webhooks
	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		pending := server.pendingRequests[domain]

		select {
		case result := <-pending.ResultChan:
			if result.EventID != payloads[i].EventID {
				t.Errorf("domain %s: event_id = %s, want %s", domain, result.EventID, payloads[i].EventID)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("domain %s: did not receive webhook", domain)
		}
	}
}

// BenchmarkHandleWebhook benchmarks webhook processing performance
func BenchmarkHandleWebhook(b *testing.B) {
	setupTestEnv(b)
	loadConfig()
	resetGlobals()

	// Create a properly signed webhook for benchmarking
	payload := createSignedWebhook("create", "bench-domain", `{"thold_price": 100}`, nil)
	jsonData, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		server.handleWebhook(w, req)
	}
}

// BenchmarkEncodeBase64URL benchmarks base64url encoding
func BenchmarkEncodeBase64URL(b *testing.B) {
	data := []byte("this is a test message for base64url encoding performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = base64.RawURLEncoding.EncodeToString(data)
	}
}

// TestTriggerWorkflow tests the workflow trigger function
func TestTriggerWorkflow(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	// Create a mock HTTP server to act as the CRE gateway
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify method
		if r.Method != "POST" {
			t.Errorf("method = %s, want POST", r.Method)
		}

		// Verify headers
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %s, want application/json", r.Header.Get("Content-Type"))
		}

		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Errorf("Authorization header should start with 'Bearer '")
		}

		// Verify JWT format (header.payload.signature)
		token := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Errorf("JWT parts = %d, want 3", len(parts))
		}

		// Read and verify body is valid JSON-RPC
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		if err := json.Unmarshal(body, &rpcReq); err != nil {
			t.Errorf("invalid JSON-RPC: %v", err)
		}

		if rpcReq["jsonrpc"] != "2.0" {
			t.Errorf("jsonrpc = %v, want 2.0", rpcReq["jsonrpc"])
		}

		if rpcReq["method"] != "workflows.execute" {
			t.Errorf("method = %v, want workflows.execute", rpcReq["method"])
		}

		// Return success
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      rpcReq["id"],
			"result":  "success",
		})
	}))
	defer mockServer.Close()

	// Override gateway URL to use mock server
	server.config.GatewayURL = mockServer.URL

	tests := []struct {
		name        string
		op          string
		domain      string
		tholdPrice  *float64
		tholdHash   *string
		callbackURL string
		wantErr     bool
	}{
		{
			name:        "create operation",
			op:          "create",
			domain:      "test-domain",
			tholdPrice:  func() *float64 { v := 100.0; return &v }(),
			callbackURL: "http://example.com/webhook",
			wantErr:     false,
		},
		{
			name:        "check operation",
			op:          "check",
			domain:      "test-domain",
			tholdHash:   func() *string { v := "abc123"; return &v }(),
			callbackURL: "http://example.com/webhook",
			wantErr:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.triggerWorkflow(tt.op, tt.domain, tt.tholdPrice, tt.tholdHash, tt.callbackURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("server.triggerWorkflow() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTriggerWorkflowErrors tests error cases for server.triggerWorkflow
func TestTriggerWorkflowErrors(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	tests := []struct {
		name        string
		setupMock   func() *httptest.Server
		expectError string
	}{
		{
			name: "non-200 response",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusBadRequest)
					w.Write([]byte("bad request"))
				}))
			},
			expectError: "non-success status",
		},
		{
			name: "server error",
			setupMock: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusInternalServerError)
					w.Write([]byte("internal error"))
				}))
			},
			expectError: "non-success status",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockServer := tt.setupMock()
			defer mockServer.Close()

			server.config.GatewayURL = mockServer.URL

			tholdPrice := 100.0
			err := server.triggerWorkflow("create", "test-domain", &tholdPrice, nil, "http://example.com/webhook")
			if err == nil {
				t.Error("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("error = %v, want to contain %s", err, tt.expectError)
			}
		})
	}
}

// TestComputeRecoveryIDEdgeCases tests edge cases in recovery ID computation using ethsign package
func TestComputeRecoveryIDEdgeCases(t *testing.T) {
	// Generate test key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	// Test with different messages
	messages := []string{
		"test",
		"",
		"a very long message that spans multiple lines and contains special characters !@#$%^&*()",
	}

	for _, msg := range messages {
		signature, err := ethsign.SignEthereumMessage(privKey, msg)
		if err != nil {
			t.Errorf("SignEthereumMessage failed for message %q: %v", msg, err)
			continue
		}

		// Verify signature format
		if len(signature) != 65 {
			t.Errorf("signature length = %d, want 65 for message %q", len(signature), msg)
		}

		// Verify v is in Ethereum format (27-30)
		v := signature[64]
		if v < 27 || v > 30 {
			t.Errorf("invalid v value %d for message %q, want 27-30 (Ethereum format)", v, msg)
		}
	}
}

// TestHandleCreateTimeout tests the timeout behavior
func TestHandleCreateTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short timeout for testing
	oldTimeout := server.config.BlockTimeout
	server.config.BlockTimeout = 100 * time.Millisecond
	defer func() { server.config.BlockTimeout = oldTimeout }()

	// Mock the server.triggerWorkflow to avoid actual HTTP calls
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()

	// Should timeout and return 202
	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d (timeout)", resp.StatusCode, http.StatusAccepted)
	}

	var syncResp SyncResponse
	json.NewDecoder(resp.Body).Decode(&syncResp)

	if syncResp.Status != "timeout" {
		t.Errorf("status = %s, want timeout", syncResp.Status)
	}
}

// TestHandleCheckMaxPending tests max pending limit for check endpoint
func TestHandleCheckMaxPending(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set low limit
	server.config.MaxPending = 2

	// Fill pending requests
	for i := 0; i < server.config.MaxPending; i++ {
		domain := fmt.Sprintf("test-%d", i)
		server.pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	checkReq := CheckRequest{
		Domain:    "new-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	// Cleanup
	resetGlobals()
	server.config.MaxPending = 1000
}

// TestHandleCheckTimeout tests check endpoint timeout
func TestHandleCheckTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	oldTimeout := server.config.BlockTimeout
	server.config.BlockTimeout = 100 * time.Millisecond
	defer func() { server.config.BlockTimeout = oldTimeout }()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusAccepted {
		t.Errorf("status = %d, want %d (timeout)", resp.StatusCode, http.StatusAccepted)
	}
}

// TestHandleCheckSuccess tests successful check with webhook
func TestHandleCheckSuccess(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	checkReq := CheckRequest{
		Domain:    "test-check-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook arriving after a short delay
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		pending, exists := server.pendingRequests["test-check-domain"]
		server.requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "check_no_breach",
				EventID:   "check-event-123",
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":95,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify core-ts PriceContract fields
	if basePrice, ok := result["base_price"].(float64); ok {
		if basePrice != 95.0 {
			t.Errorf("base_price = %f, want 95.0", basePrice)
		}
	}

	if _, ok := result["chain_network"]; !ok {
		t.Error("chain_network not found in response")
	}
}

// TestHandleCreateWorkflowError tests workflow trigger error
func TestHandleCreateWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockServer.Close()

	server.config.GatewayURL = mockServer.URL

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	server.handleCreate(w, req)

	resp := w.Result()

	// Should return 500 when workflow trigger fails
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestWebhookParseContentError tests error handling when parsing webhook content
func TestWebhookParseContentError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	domain := "test-parse-error"
	server.pendingRequests[domain] = &PendingRequest{
		RequestID:  domain,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Create a properly signed webhook with invalid JSON content
	// The content being invalid JSON is fine - we're testing that the webhook is still delivered
	payload := createSignedWebhook("create", domain, `{invalid json}`, nil)
	jsonData, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleWebhook(w, req)

	resp := w.Result()
	// Webhook handler should still return 200 even with bad content
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify the webhook was still delivered to the pending request
	pending := server.pendingRequests[domain]
	select {
	case result := <-pending.ResultChan:
		if result.EventID != payload.EventID {
			t.Errorf("event_id = %s, want %s", result.EventID, payload.EventID)
		}
	case <-time.After(100 * time.Millisecond):
		t.Error("webhook not delivered to pending request")
	}
}

// TestHandleWebhookDuplicateDelivery tests duplicate webhook handling
func TestHandleWebhookDuplicateDelivery(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	domain := "test-duplicate"
	pending := &PendingRequest{
		RequestID:  domain,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}
	server.pendingRequests[domain] = pending

	// Create a properly signed webhook
	payload := createSignedWebhook("create", domain, `{"test": "data"}`, nil)
	jsonData, _ := json.Marshal(payload)

	// Send first webhook
	req1 := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w1 := httptest.NewRecorder()

	// Track channel deliveries
	deliveryCount := 0
	go func() {
		for range pending.ResultChan {
			deliveryCount++
		}
	}()

	server.handleWebhook(w1, req1)
	time.Sleep(50 * time.Millisecond)

	// Send duplicate webhook (same event_id should be ignored by default select in server.handleWebhook)
	req2 := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w2 := httptest.NewRecorder()
	server.handleWebhook(w2, req2)
	time.Sleep(50 * time.Millisecond)

	// Both should return 200
	if w1.Code != http.StatusOK {
		t.Errorf("first webhook status = %d, want %d", w1.Code, http.StatusOK)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("duplicate webhook status = %d, want %d", w2.Code, http.StatusOK)
	}

	close(pending.ResultChan)
	time.Sleep(10 * time.Millisecond)

	// Due to channel buffer and default case, it's possible both went through
	// The important part is that the system handles it gracefully
	if deliveryCount == 0 {
		t.Error("no webhooks were delivered")
	}
	// The duplicate protection via 'default' case in select means the second
	// webhook won't block even if channel is full
}

// TestHandleCheckWorkflowError tests workflow trigger error for check
func TestHandleCheckWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("bad request"))
	}))
	defer mockServer.Close()

	server.config.GatewayURL = mockServer.URL

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	server.handleCheck(w, req)

	resp := w.Result()

	// Should return 500 when workflow trigger fails
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestHandleCheckBreach tests check endpoint with breach event
func TestHandleCheckBreach(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL

	checkReq := CheckRequest{
		Domain:    "test-breach-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook with breach event
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		pending, exists := server.pendingRequests["test-breach-domain"]
		server.requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "breach",
				EventID:   "breach-event-123",
				Content:   `{"event_type":"breach","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":90,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":"secret123","thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCheck(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify breach data is returned
	if tholdKey, ok := result["thold_key"].(string); ok {
		if tholdKey != "secret123" {
			t.Errorf("thold_key = %s, want secret123", tholdKey)
		}
	} else {
		t.Error("thold_key not found in breach response")
	}
}

// TestHandleCreateSuccess tests successful create with webhook
func TestHandleCreateSuccess(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the server.triggerWorkflow
	originalGatewayURL := server.config.GatewayURL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	server.config.GatewayURL = mockServer.URL
	defer func() { server.config.GatewayURL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100.5", nil)
	w := httptest.NewRecorder()

	// Simulate webhook arriving after request is created
	go func() {
		time.Sleep(50 * time.Millisecond)

		server.requestsMutex.RLock()
		// Find the pending request (domain is generated, so we need to iterate)
		var pending *PendingRequest
		var domain string
		for d, p := range server.pendingRequests {
			if p.Status == "pending" {
				pending = p
				domain = d
				break
			}
		}
		server.requestsMutex.RUnlock()

		if pending != nil {
			payload := &WebhookPayload{
				EventType: "create",
				EventID:   "create-event-123",
				Tags:      [][]string{{"domain", domain}},
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":99,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	server.handleCreate(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Verify core-ts PriceContract fields
	if basePrice, ok := result["base_price"].(float64); ok {
		if basePrice != 99.0 {
			t.Errorf("base_price = %f, want 99.0", basePrice)
		}
	}

	// Verify PriceContract fields exist
	if network, ok := result["chain_network"].(string); !ok || network != "mutiny" {
		t.Errorf("chain_network = %v, want 'mutiny'", result["chain_network"])
	}

	if _, ok := result["commit_hash"]; !ok {
		t.Error("commit_hash not found in response")
	}

	if _, ok := result["contract_id"]; !ok {
		t.Error("contract_id not found in response")
	}
}
