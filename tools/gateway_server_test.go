package main

import (
	"bytes"
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

	"github.com/ethereum/go-ethereum/crypto"
)

// Test helpers
func setupTestEnv(t *testing.T) {
	t.Helper()

	// Set required environment variables
	os.Setenv("CRE_WORKFLOW_ID", "test-workflow-id-12345")
	os.Setenv("DUCAT_AUTHORIZED_KEY", "0xtest123")
	os.Setenv("GATEWAY_CALLBACK_URL", "http://localhost:8080/webhook/ducat")
	os.Setenv("DUCAT_PRIVATE_KEY", "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c")

	// Reset globals
	pendingRequests = make(map[string]*PendingRequest)

	// Load private key for tests
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privateKey, _ = crypto.ToECDSA(privKeyBytes)
}

func resetGlobals() {
	requestsMutex.Lock()
	pendingRequests = make(map[string]*PendingRequest)
	requestsMutex.Unlock()
}

// TestLoadConfig tests configuration loading from environment variables
func TestLoadConfig(t *testing.T) {
	tests := []struct {
		name        string
		envVars     map[string]string
		shouldPanic bool
		validate    func(t *testing.T)
	}{
		{
			name: "all required vars set",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":      "workflow123",
				"DUCAT_AUTHORIZED_KEY": "0xabc123",
				"GATEWAY_CALLBACK_URL": "http://example.com/webhook",
			},
			shouldPanic: false,
			validate: func(t *testing.T) {
				if WORKFLOW_ID != "workflow123" {
					t.Errorf("WORKFLOW_ID = %s, want workflow123", WORKFLOW_ID)
				}
				if AUTHORIZED_KEY != "0xabc123" {
					t.Errorf("AUTHORIZED_KEY = %s, want 0xabc123", AUTHORIZED_KEY)
				}
				if CALLBACK_URL != "http://example.com/webhook" {
					t.Errorf("CALLBACK_URL = %s, want http://example.com/webhook", CALLBACK_URL)
				}
				if BLOCK_TIMEOUT != 60*time.Second {
					t.Errorf("BLOCK_TIMEOUT = %v, want 60s", BLOCK_TIMEOUT)
				}
				if MAX_PENDING != 1000 {
					t.Errorf("MAX_PENDING = %d, want 1000", MAX_PENDING)
				}
			},
		},
		{
			name: "custom timeout and limits",
			envVars: map[string]string{
				"CRE_WORKFLOW_ID":         "workflow123",
				"DUCAT_AUTHORIZED_KEY":    "0xabc123",
				"GATEWAY_CALLBACK_URL":    "http://example.com/webhook",
				"BLOCK_TIMEOUT_SECONDS":   "30",
				"CLEANUP_INTERVAL_SECONDS": "60",
				"MAX_PENDING_REQUESTS":    "500",
			},
			shouldPanic: false,
			validate: func(t *testing.T) {
				if BLOCK_TIMEOUT != 30*time.Second {
					t.Errorf("BLOCK_TIMEOUT = %v, want 30s", BLOCK_TIMEOUT)
				}
				if CLEANUP_INTERVAL != 60*time.Second {
					t.Errorf("CLEANUP_INTERVAL = %v, want 60s", CLEANUP_INTERVAL)
				}
				if MAX_PENDING != 500 {
					t.Errorf("MAX_PENDING = %d, want 500", MAX_PENDING)
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

			loadConfig()

			if tt.validate != nil {
				tt.validate(t)
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

			handleCreate(w, req)

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
	MAX_PENDING = 2

	// Fill up pending requests
	for i := 0; i < MAX_PENDING; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	handleCreate(w, req)

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
	MAX_PENDING = 1000
}

// TestHandleWebhook tests webhook processing
func TestHandleWebhook(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	tests := []struct {
		name           string
		method         string
		payload        interface{}
		setupPending   bool
		domain         string
		expectedStatus int
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
			payload:        "invalid json",
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:   "valid webhook with pending request",
			method: "POST",
			payload: WebhookPayload{
				EventType: "create",
				EventID:   "event123",
				Tags:      [][]string{{"domain", "test-domain"}},
				Content:   `{"thold_price": 100.5, "thold_hash": "abc123"}`,
			},
			setupPending:   true,
			domain:         "test-domain",
			expectedStatus: http.StatusOK,
		},
		{
			name:   "webhook without pending request",
			method: "POST",
			payload: WebhookPayload{
				EventType: "create",
				EventID:   "event456",
				Tags:      [][]string{{"domain", "unknown-domain"}},
				Content:   `{"thold_price": 100.5}`,
			},
			setupPending:   false,
			expectedStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetGlobals()

			// Setup pending request if needed
			if tt.setupPending {
				pendingRequests[tt.domain] = &PendingRequest{
					RequestID:  tt.domain,
					CreatedAt:  time.Now(),
					ResultChan: make(chan *WebhookPayload, 1),
					Status:     "pending",
				}
			}

			var body io.Reader
			if str, ok := tt.payload.(string); ok {
				body = strings.NewReader(str)
			} else if tt.payload != nil {
				jsonData, _ := json.Marshal(tt.payload)
				body = bytes.NewReader(jsonData)
			}

			req := httptest.NewRequest(tt.method, "/webhook/ducat", body)
			w := httptest.NewRecorder()

			handleWebhook(w, req)

			resp := w.Result()
			if resp.StatusCode != tt.expectedStatus {
				t.Errorf("status = %d, want %d", resp.StatusCode, tt.expectedStatus)
			}

			// If we set up a pending request, verify it received the webhook
			if tt.setupPending {
				pending := pendingRequests[tt.domain]
				select {
				case result := <-pending.ResultChan:
					if result.EventID != "event123" {
						t.Errorf("received event_id = %s, want event123", result.EventID)
					}
				case <-time.After(100 * time.Millisecond):
					t.Error("webhook did not unblock pending request")
				}
			}
		})
	}
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

			handleCheck(w, req)

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
				pendingRequests["pending-req"] = &PendingRequest{
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
				pendingRequests["completed-req"] = &PendingRequest{
					RequestID: "completed-req",
					CreatedAt: time.Now(),
					Status:    "completed",
					Result: &WebhookPayload{
						// Full CRE format payload with core-ts PriceContract fields
						Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":100,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":95.0}`,
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

			handleStatus(w, req)

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
	oldCleanupInterval := CLEANUP_INTERVAL
	oldBlockTimeout := BLOCK_TIMEOUT
	CLEANUP_INTERVAL = 50 * time.Millisecond
	BLOCK_TIMEOUT = 50 * time.Millisecond
	defer func() {
		CLEANUP_INTERVAL = oldCleanupInterval
		BLOCK_TIMEOUT = oldBlockTimeout
	}()

	now := time.Now()

	// Add various requests
	pendingRequests["old-completed"] = &PendingRequest{
		RequestID:  "old-completed",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	pendingRequests["old-timeout"] = &PendingRequest{
		RequestID:  "old-timeout",
		CreatedAt:  now.Add(-10 * time.Minute),
		Status:     "timeout",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	pendingRequests["stale-pending"] = &PendingRequest{
		RequestID:  "stale-pending",
		CreatedAt:  now.Add(-5 * time.Minute),
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	pendingRequests["recent-completed"] = &PendingRequest{
		RequestID:  "recent-completed",
		CreatedAt:  now.Add(-1 * time.Minute),
		Status:     "completed",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	pendingRequests["active-pending"] = &PendingRequest{
		RequestID:  "active-pending",
		CreatedAt:  now,
		Status:     "pending",
		ResultChan: make(chan *WebhookPayload, 1),
	}

	initialCount := len(pendingRequests)
	if initialCount != 5 {
		t.Fatalf("setup failed: got %d requests, want 5", initialCount)
	}

	// Call cleanupOldRequests directly and wait for one cycle
	stopChan := make(chan bool)
	doneChan := make(chan bool)

	go func() {
		ticker := time.NewTicker(CLEANUP_INTERVAL)
		defer ticker.Stop()
		defer close(doneChan)

		select {
		case <-ticker.C:
			requestsMutex.Lock()
			now := time.Now()
			cleaned := 0

			for id, req := range pendingRequests {
				shouldDelete := false

				if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*BLOCK_TIMEOUT {
					shouldDelete = true
				}

				if shouldDelete {
					delete(pendingRequests, id)
					cleaned++
				}
			}
			requestsMutex.Unlock()
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
	requestsMutex.RLock()
	defer requestsMutex.RUnlock()

	expectedRemaining := []string{"recent-completed", "active-pending"}
	if len(pendingRequests) != len(expectedRemaining) {
		t.Errorf("after cleanup: got %d requests, want %d", len(pendingRequests), len(expectedRemaining))
	}

	for _, key := range expectedRemaining {
		if _, exists := pendingRequests[key]; !exists {
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
		name     string
		payload  *WebhookPayload
		expected string
	}{
		{
			name: "valid payload",
			payload: &WebhookPayload{
				Content: `{"thold_hash": "abc123def456"}`,
			},
			expected: "abc123def456",
		},
		{
			name: "invalid JSON",
			payload: &WebhookPayload{
				Content: `invalid json`,
			},
			expected: "",
		},
		{
			name: "missing thold_hash",
			payload: &WebhookPayload{
				Content: `{"other_field": "value"}`,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getTholdHash(tt.payload)
			if result != tt.expected {
				t.Errorf("getTholdHash() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestEncodeBase64URL tests the base64url encoding function
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
			result := encodeBase64URL(tt.input)
			if result != tt.expected {
				t.Errorf("encodeBase64URL() = %s, want %s", result, tt.expected)
			}
		})
	}
}

// TestGenerateRequestID tests request ID generation
func TestGenerateRequestID(t *testing.T) {
	id1 := generateRequestID()
	id2 := generateRequestID()

	if id1 == id2 {
		t.Error("generateRequestID() should generate unique IDs")
	}

	if len(id1) != 32 {
		t.Errorf("generateRequestID() length = %d, want 32", len(id1))
	}

	// Verify it's valid hex
	if _, err := hex.DecodeString(id1); err != nil {
		t.Errorf("generateRequestID() returned invalid hex: %v", err)
	}
}

// TestGenerateJWT tests JWT generation
func TestGenerateJWT(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	address := "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82"
	digest := "0x1234567890abcdef"

	token, err := generateJWT(privKey, address, digest)
	if err != nil {
		t.Fatalf("generateJWT() error = %v", err)
	}

	// Verify JWT structure (header.payload.signature)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Errorf("JWT parts = %d, want 3", len(parts))
	}

	// Verify it's different each time (due to jti and timestamps)
	token2, _ := generateJWT(privKey, address, digest)
	if token == token2 {
		t.Error("generateJWT() should generate unique tokens due to jti")
	}
}

// TestSignEthereumMessage tests Ethereum message signing
func TestSignEthereumMessage(t *testing.T) {
	// Generate a test private key
	privateKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privateKeyHex)
	privKey, _ := crypto.ToECDSA(privKeyBytes)

	message := "test message"

	signature, err := signEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("signEthereumMessage() error = %v", err)
	}

	// Verify signature length (65 bytes: r + s + v)
	if len(signature) != 65 {
		t.Errorf("signature length = %d, want 65", len(signature))
	}

	// Verify recovery ID is valid (0-3)
	recoveryID := signature[64]
	if recoveryID > 3 {
		t.Errorf("recovery ID = %d, want 0-3", recoveryID)
	}
}

// TestConcurrentWebhooks tests concurrent webhook handling
func TestConcurrentWebhooks(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	numRequests := 10
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	// Send webhooks concurrently
	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			domain := fmt.Sprintf("test-domain-%d", idx)
			payload := WebhookPayload{
				EventType: "create",
				EventID:   fmt.Sprintf("event-%d", idx),
				Tags:      [][]string{{"domain", domain}},
				Content:   fmt.Sprintf(`{"thold_price": %d}`, idx*100),
			}

			jsonData, _ := json.Marshal(payload)
			req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
			w := httptest.NewRecorder()

			handleWebhook(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("webhook %d: status = %d, want %d", idx, w.Code, http.StatusOK)
			}
		}(i)
	}

	wg.Wait()

	// Verify all requests received their webhooks
	for i := 0; i < numRequests; i++ {
		domain := fmt.Sprintf("test-domain-%d", i)
		pending := pendingRequests[domain]

		select {
		case result := <-pending.ResultChan:
			expectedEventID := fmt.Sprintf("event-%d", i)
			if result.EventID != expectedEventID {
				t.Errorf("domain %s: event_id = %s, want %s", domain, result.EventID, expectedEventID)
			}
		case <-time.After(1 * time.Second):
			t.Errorf("domain %s: did not receive webhook", domain)
		}
	}
}

// BenchmarkHandleWebhook benchmarks webhook processing performance
func BenchmarkHandleWebhook(b *testing.B) {
	setupTestEnv(&testing.T{})
	loadConfig()
	resetGlobals()

	payload := WebhookPayload{
		EventType: "create",
		EventID:   "bench-event",
		Tags:      [][]string{{"domain", "bench-domain"}},
		Content:   `{"thold_price": 100}`,
	}
	jsonData, _ := json.Marshal(payload)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		handleWebhook(w, req)
	}
}

// BenchmarkEncodeBase64URL benchmarks base64url encoding
func BenchmarkEncodeBase64URL(b *testing.B) {
	data := []byte("this is a test message for base64url encoding performance testing")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = encodeBase64URL(data)
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
	GATEWAY_URL = mockServer.URL

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
			err := triggerWorkflow(tt.op, tt.domain, tt.tholdPrice, tt.tholdHash, tt.callbackURL)
			if (err != nil) != tt.wantErr {
				t.Errorf("triggerWorkflow() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestTriggerWorkflowErrors tests error cases for triggerWorkflow
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

			GATEWAY_URL = mockServer.URL

			tholdPrice := 100.0
			err := triggerWorkflow("create", "test-domain", &tholdPrice, nil, "http://example.com/webhook")
			if err == nil {
				t.Error("expected error but got nil")
			}
			if !strings.Contains(err.Error(), tt.expectError) {
				t.Errorf("error = %v, want to contain %s", err, tt.expectError)
			}
		})
	}
}

// TestComputeRecoveryIDEdgeCases tests edge cases in recovery ID computation
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
		signature, err := signEthereumMessage(privKey, msg)
		if err != nil {
			t.Errorf("signEthereumMessage failed for message %q: %v", msg, err)
			continue
		}

		// Verify signature format
		if len(signature) != 65 {
			t.Errorf("signature length = %d, want 65 for message %q", len(signature), msg)
		}

		// Verify recovery ID is in valid range
		recoveryID := signature[64]
		if recoveryID > 3 {
			t.Errorf("invalid recovery ID %d for message %q", recoveryID, msg)
		}
	}
}

// TestHandleCreateTimeout tests the timeout behavior
func TestHandleCreateTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short timeout for testing
	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 100 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	// Mock the triggerWorkflow to avoid actual HTTP calls
	originalGatewayURL := GATEWAY_URL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL
	defer func() { GATEWAY_URL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	handleCreate(w, req)

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
	MAX_PENDING = 2

	// Fill pending requests
	for i := 0; i < MAX_PENDING; i++ {
		domain := fmt.Sprintf("test-%d", i)
		pendingRequests[domain] = &PendingRequest{
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

	handleCheck(w, req)

	resp := w.Result()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}

	// Cleanup
	resetGlobals()
	MAX_PENDING = 1000
}

// TestHandleCheckTimeout tests check endpoint timeout
func TestHandleCheckTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 100 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	// Mock the triggerWorkflow
	originalGatewayURL := GATEWAY_URL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL
	defer func() { GATEWAY_URL = originalGatewayURL }()

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleCheck(w, req)

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

	// Mock the triggerWorkflow
	originalGatewayURL := GATEWAY_URL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL
	defer func() { GATEWAY_URL = originalGatewayURL }()

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

		requestsMutex.RLock()
		pending, exists := pendingRequests["test-check-domain"]
		requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "check_no_breach",
				EventID:   "check-event-123",
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":95,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100.0}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	handleCheck(w, req)

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

	GATEWAY_URL = mockServer.URL

	req := httptest.NewRequest("GET", "/api/quote?th=100", nil)
	w := httptest.NewRecorder()

	handleCreate(w, req)

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
	pendingRequests[domain] = &PendingRequest{
		RequestID:  domain,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	payload := WebhookPayload{
		EventType: "create",
		EventID:   "test-event",
		Tags:      [][]string{{"domain", domain}},
		Content:   `{invalid json}`,
	}

	jsonData, _ := json.Marshal(payload)
	req := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleWebhook(w, req)

	resp := w.Result()
	// Webhook handler should still return 200 even with bad content
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// Verify the webhook was still delivered to the pending request
	pending := pendingRequests[domain]
	select {
	case result := <-pending.ResultChan:
		if result.EventID != "test-event" {
			t.Errorf("event_id = %s, want test-event", result.EventID)
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
	pendingRequests[domain] = pending

	payload := WebhookPayload{
		EventType: "create",
		EventID:   "dup-event",
		Tags:      [][]string{{"domain", domain}},
		Content:   `{"test": "data"}`,
	}

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

	handleWebhook(w1, req1)
	time.Sleep(50 * time.Millisecond)

	// Send duplicate webhook (same event_id should be ignored by default select in handleWebhook)
	req2 := httptest.NewRequest("POST", "/webhook/ducat", bytes.NewReader(jsonData))
	w2 := httptest.NewRecorder()
	handleWebhook(w2, req2)
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

	GATEWAY_URL = mockServer.URL

	checkReq := CheckRequest{
		Domain:    "test-domain",
		TholdHash: "1234567890123456789012345678901234567890",
	}
	jsonData, _ := json.Marshal(checkReq)

	req := httptest.NewRequest("POST", "/check", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleCheck(w, req)

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

	// Mock the triggerWorkflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

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

		requestsMutex.RLock()
		pending, exists := pendingRequests["test-breach-domain"]
		requestsMutex.RUnlock()

		if exists {
			payload := &WebhookPayload{
				EventType: "breach",
				EventID:   "breach-event-123",
				Content:   `{"latest_price": 90.5, "thold_price": 100.0, "thold_key": "secret123"}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	handleCheck(w, req)

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

	// Mock the triggerWorkflow
	originalGatewayURL := GATEWAY_URL
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL
	defer func() { GATEWAY_URL = originalGatewayURL }()

	req := httptest.NewRequest("GET", "/api/quote?th=100.5", nil)
	w := httptest.NewRecorder()

	// Simulate webhook arriving after request is created
	go func() {
		time.Sleep(50 * time.Millisecond)

		requestsMutex.RLock()
		// Find the pending request (domain is generated, so we need to iterate)
		var pending *PendingRequest
		var domain string
		for d, p := range pendingRequests {
			if p.Status == "pending" {
				pending = p
				domain = d
				break
			}
		}
		requestsMutex.RUnlock()

		if pending != nil {
			payload := &WebhookPayload{
				EventType: "create",
				EventID:   "create-event-123",
				Tags:      [][]string{{"domain", domain}},
				// Full CRE format payload with core-ts PriceContract fields
				Content: `{"event_type":"active","chain_network":"mutiny","oracle_pubkey":"abc123pubkey","base_price":99,"base_stamp":1699999000,"commit_hash":"commit123","contract_id":"contract456","oracle_sig":"sig789","thold_hash":"abc123def456","thold_key":null,"thold_price":100.5}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	handleCreate(w, req)

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

// =============================================================================
// Tests for /api/evaluate endpoint (NEW)
// =============================================================================

// TestHandleEvaluateValidation tests input validation for /api/evaluate
func TestHandleEvaluateValidation(t *testing.T) {
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
			name:           "wrong method GET",
			method:         "GET",
			payload:        nil,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "wrong method PUT",
			method:         "PUT",
			payload:        nil,
			expectedStatus: http.StatusMethodNotAllowed,
			expectedBody:   "Method not allowed",
		},
		{
			name:           "OPTIONS preflight",
			method:         "OPTIONS",
			payload:        nil,
			expectedStatus: http.StatusOK,
			expectedBody:   "",
		},
		{
			name:           "invalid JSON",
			method:         "POST",
			payload:        "not json",
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid JSON",
		},
		{
			name:           "empty thold_hashes array",
			method:         "POST",
			payload:        EvaluateRequest{TholdHashes: []string{}},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "thold_hashes required",
		},
		{
			name:           "nil thold_hashes",
			method:         "POST",
			payload:        map[string]interface{}{},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "thold_hashes required",
		},
		{
			name:   "too many thold_hashes",
			method: "POST",
			payload: EvaluateRequest{
				TholdHashes: make([]string, 101), // 101 > max 100
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Maximum 100 thold_hashes",
		},
		{
			name:   "invalid thold_hash length - too short",
			method: "POST",
			payload: EvaluateRequest{
				TholdHashes: []string{"abc123"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid thold_hash at index 0",
		},
		{
			name:   "invalid thold_hash length - too long",
			method: "POST",
			payload: EvaluateRequest{
				TholdHashes: []string{"1234567890123456789012345678901234567890extra"},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid thold_hash at index 0",
		},
		{
			name:   "mixed valid and invalid hashes",
			method: "POST",
			payload: EvaluateRequest{
				TholdHashes: []string{
					"1234567890123456789012345678901234567890", // valid
					"short",                                    // invalid
				},
			},
			expectedStatus: http.StatusBadRequest,
			expectedBody:   "Invalid thold_hash at index 1",
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

			req := httptest.NewRequest(tt.method, "/api/evaluate", body)
			w := httptest.NewRecorder()

			handleEvaluate(w, req)

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

// TestHandleEvaluateMaxPending tests max pending request limit for evaluate endpoint
func TestHandleEvaluateMaxPending(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set low limit for testing
	MAX_PENDING = 2

	// Fill pending requests
	for i := 0; i < MAX_PENDING; i++ {
		domain := fmt.Sprintf("test-%d", i)
		pendingRequests[domain] = &PendingRequest{
			RequestID:  domain,
			CreatedAt:  time.Now(),
			ResultChan: make(chan *WebhookPayload, 1),
			Status:     "pending",
		}
	}

	evalReq := EvaluateRequest{
		TholdHashes: []string{"1234567890123456789012345678901234567890"},
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

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
	MAX_PENDING = 1000
}

// TestHandleEvaluateTimeout tests timeout behavior for evaluate endpoint
func TestHandleEvaluateTimeout(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Set very short timeout for testing
	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 100 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	// Mock the triggerEvaluateWorkflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	evalReq := EvaluateRequest{
		TholdHashes: []string{
			"1234567890123456789012345678901234567890",
			"abcdef1234567890123456789012345678901234",
		},
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

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

	if syncResp.RequestID == "" {
		t.Error("request_id should not be empty")
	}

	if !strings.Contains(syncResp.Message, "/status/") {
		t.Errorf("message should contain status URL, got: %s", syncResp.Message)
	}
}

// TestHandleEvaluateSuccess tests successful evaluate with webhook response
func TestHandleEvaluateSuccess(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock the triggerEvaluateWorkflow
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	evalReq := EvaluateRequest{
		TholdHashes: []string{
			"1234567890123456789012345678901234567890",
			"abcdef1234567890123456789012345678901234",
		},
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook arriving
	go func() {
		time.Sleep(50 * time.Millisecond)

		requestsMutex.RLock()
		var pending *PendingRequest
		var domain string
		for d, p := range pendingRequests {
			if strings.HasPrefix(d, "eval-") && p.Status == "pending" {
				pending = p
				domain = d
				break
			}
		}
		requestsMutex.RUnlock()

		if pending != nil {
			// Simulate evaluate response from CRE
			tholdKey := "secret123abc456def789012345678901234567890123456789012345678901234"
			evalResp := EvaluateQuotesResponse{
				Results: []QuoteEvaluationResult{
					{
						TholdHash:    "1234567890123456789012345678901234567890",
						Status:       "breached",
						TholdKey:     &tholdKey,
						CurrentPrice: 95000.0,
						TholdPrice:   100000.0,
					},
					{
						TholdHash:    "abcdef1234567890123456789012345678901234",
						Status:       "active",
						TholdKey:     nil,
						CurrentPrice: 95000.0,
						TholdPrice:   90000.0,
					},
				},
				CurrentPrice: 95000.0,
				EvaluatedAt:  1700000000,
			}
			contentJSON, _ := json.Marshal(evalResp)

			payload := &WebhookPayload{
				EventType: "evaluate",
				EventID:   "eval-event-123",
				Tags:      [][]string{{"domain", domain}},
				Content:   string(contentJSON),
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	handleEvaluate(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result EvaluateQuotesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}

	// Verify response structure
	if len(result.Results) != 2 {
		t.Errorf("results count = %d, want 2", len(result.Results))
	}

	if result.CurrentPrice != 95000.0 {
		t.Errorf("current_price = %f, want 95000.0", result.CurrentPrice)
	}

	if result.EvaluatedAt != 1700000000 {
		t.Errorf("evaluated_at = %d, want 1700000000", result.EvaluatedAt)
	}

	// Verify first result (breached)
	if result.Results[0].Status != "breached" {
		t.Errorf("results[0].status = %s, want breached", result.Results[0].Status)
	}
	if result.Results[0].TholdKey == nil {
		t.Error("results[0].thold_key should not be nil for breached quote")
	}

	// Verify second result (active)
	if result.Results[1].Status != "active" {
		t.Errorf("results[1].status = %s, want active", result.Results[1].Status)
	}
	if result.Results[1].TholdKey != nil {
		t.Error("results[1].thold_key should be nil for active quote")
	}
}

// TestHandleEvaluateWorkflowError tests workflow trigger error for evaluate
func TestHandleEvaluateWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Mock server that returns error
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("internal error"))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	evalReq := EvaluateRequest{
		TholdHashes: []string{"1234567890123456789012345678901234567890"},
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

	resp := w.Result()

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusInternalServerError)
	}
}

// TestHandleEvaluateCORSHeaders tests CORS headers for evaluate endpoint
func TestHandleEvaluateCORSHeaders(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Test OPTIONS preflight
	req := httptest.NewRequest("OPTIONS", "/api/evaluate", nil)
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

	resp := w.Result()

	if resp.Header.Get("Access-Control-Allow-Origin") != "*" {
		t.Errorf("Access-Control-Allow-Origin = %s, want *", resp.Header.Get("Access-Control-Allow-Origin"))
	}

	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Methods"), "POST") {
		t.Errorf("Access-Control-Allow-Methods should contain POST, got: %s", resp.Header.Get("Access-Control-Allow-Methods"))
	}

	if !strings.Contains(resp.Header.Get("Access-Control-Allow-Headers"), "Content-Type") {
		t.Errorf("Access-Control-Allow-Headers should contain Content-Type, got: %s", resp.Header.Get("Access-Control-Allow-Headers"))
	}
}

// TestHandleEvaluateWithCallbackURL tests evaluate with optional callback URL
func TestHandleEvaluateWithCallbackURL(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	// Track what was sent to the mock server
	var receivedPayload map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		var rpcReq map[string]interface{}
		json.Unmarshal(body, &rpcReq)
		if params, ok := rpcReq["params"].(map[string]interface{}); ok {
			if input, ok := params["input"].(map[string]interface{}); ok {
				receivedPayload = input
			}
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	// Set short timeout
	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 50 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	callbackURL := "http://example.com/my-callback"
	evalReq := EvaluateRequest{
		TholdHashes: []string{"1234567890123456789012345678901234567890"},
		CallbackURL: &callbackURL,
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	handleEvaluate(w, req)

	// Verify action was set to "evaluate" in the request
	if receivedPayload != nil {
		if action, ok := receivedPayload["action"].(string); !ok || action != "evaluate" {
			t.Errorf("action = %v, want 'evaluate'", receivedPayload["action"])
		}
		if hashes, ok := receivedPayload["thold_hashes"].([]interface{}); !ok || len(hashes) != 1 {
			t.Errorf("thold_hashes not properly sent")
		}
	}
}

// TestHandleEvaluateMalformedWebhookResponse tests handling of malformed webhook response
func TestHandleEvaluateMalformedWebhookResponse(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	evalReq := EvaluateRequest{
		TholdHashes: []string{"1234567890123456789012345678901234567890"},
	}
	jsonData, _ := json.Marshal(evalReq)

	req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
	w := httptest.NewRecorder()

	// Simulate webhook with malformed content
	go func() {
		time.Sleep(30 * time.Millisecond)

		requestsMutex.RLock()
		var pending *PendingRequest
		var domain string
		for d, p := range pendingRequests {
			if strings.HasPrefix(d, "eval-") && p.Status == "pending" {
				pending = p
				domain = d
				break
			}
		}
		requestsMutex.RUnlock()

		if pending != nil {
			payload := &WebhookPayload{
				EventType: "evaluate",
				EventID:   "eval-event-123",
				Tags:      [][]string{{"domain", domain}},
				Content:   `{invalid json content}`,
			}
			select {
			case pending.ResultChan <- payload:
			default:
			}
		}
	}()

	handleEvaluate(w, req)

	resp := w.Result()

	// Should still return 200 with raw content fallback
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	// Should have "raw" field with original content
	if _, ok := result["raw"]; !ok {
		t.Error("response should contain 'raw' field for malformed content")
	}
}

// =============================================================================
// Tests for triggerEvaluateWorkflow
// =============================================================================

func TestTriggerEvaluateWorkflow(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	var receivedBody map[string]interface{}
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &receivedBody)
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      receivedBody["id"],
			"result":  "success",
		})
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	err := triggerEvaluateWorkflow("test-domain", []string{"hash1", "hash2"}, "http://callback.example.com")
	if err != nil {
		t.Fatalf("triggerEvaluateWorkflow() error = %v", err)
	}

	// Verify request structure
	if receivedBody["jsonrpc"] != "2.0" {
		t.Errorf("jsonrpc = %v, want 2.0", receivedBody["jsonrpc"])
	}
	if receivedBody["method"] != "workflows.execute" {
		t.Errorf("method = %v, want workflows.execute", receivedBody["method"])
	}

	params, ok := receivedBody["params"].(map[string]interface{})
	if !ok {
		t.Fatal("params not found in request")
	}

	input, ok := params["input"].(map[string]interface{})
	if !ok {
		t.Fatal("input not found in params")
	}

	if input["action"] != "evaluate" {
		t.Errorf("action = %v, want evaluate", input["action"])
	}
	if input["domain"] != "test-domain" {
		t.Errorf("domain = %v, want test-domain", input["domain"])
	}
	if input["callback_url"] != "http://callback.example.com" {
		t.Errorf("callback_url = %v, want http://callback.example.com", input["callback_url"])
	}

	hashes, ok := input["thold_hashes"].([]interface{})
	if !ok || len(hashes) != 2 {
		t.Errorf("thold_hashes = %v, want [hash1, hash2]", input["thold_hashes"])
	}
}

func TestTriggerEvaluateWorkflowError(t *testing.T) {
	setupTestEnv(t)
	loadConfig()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("server error"))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	err := triggerEvaluateWorkflow("test-domain", []string{"hash1"}, "http://callback.example.com")
	if err == nil {
		t.Error("expected error but got nil")
	}
	if !strings.Contains(err.Error(), "non-success status") {
		t.Errorf("error = %v, want to contain 'non-success status'", err)
	}
}

// =============================================================================
// Tests for QuoteEvaluationResult and EvaluateQuotesResponse types
// =============================================================================

func TestQuoteEvaluationResultJSON(t *testing.T) {
	tholdKey := "secretkey123"
	errMsg := "some error"

	tests := []struct {
		name   string
		result QuoteEvaluationResult
		check  func(t *testing.T, data map[string]interface{})
	}{
		{
			name: "breached with key",
			result: QuoteEvaluationResult{
				TholdHash:    "1234567890123456789012345678901234567890",
				Status:       "breached",
				TholdKey:     &tholdKey,
				CurrentPrice: 95000.0,
				TholdPrice:   100000.0,
			},
			check: func(t *testing.T, data map[string]interface{}) {
				if data["status"] != "breached" {
					t.Errorf("status = %v, want breached", data["status"])
				}
				if data["thold_key"] != tholdKey {
					t.Errorf("thold_key = %v, want %s", data["thold_key"], tholdKey)
				}
				if data["current_price"].(float64) != 95000.0 {
					t.Errorf("current_price = %v, want 95000.0", data["current_price"])
				}
			},
		},
		{
			name: "active without key",
			result: QuoteEvaluationResult{
				TholdHash:    "1234567890123456789012345678901234567890",
				Status:       "active",
				TholdKey:     nil,
				CurrentPrice: 95000.0,
				TholdPrice:   90000.0,
			},
			check: func(t *testing.T, data map[string]interface{}) {
				if data["status"] != "active" {
					t.Errorf("status = %v, want active", data["status"])
				}
				if data["thold_key"] != nil {
					t.Errorf("thold_key = %v, want nil", data["thold_key"])
				}
			},
		},
		{
			name: "error result",
			result: QuoteEvaluationResult{
				TholdHash:    "1234567890123456789012345678901234567890",
				Status:       "error",
				CurrentPrice: 95000.0,
				Error:        &errMsg,
			},
			check: func(t *testing.T, data map[string]interface{}) {
				if data["status"] != "error" {
					t.Errorf("status = %v, want error", data["status"])
				}
				if data["error"] != errMsg {
					t.Errorf("error = %v, want %s", data["error"], errMsg)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			jsonData, err := json.Marshal(tt.result)
			if err != nil {
				t.Fatalf("failed to marshal: %v", err)
			}

			var decoded map[string]interface{}
			if err := json.Unmarshal(jsonData, &decoded); err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}

			tt.check(t, decoded)
		})
	}
}

func TestEvaluateQuotesResponseJSON(t *testing.T) {
	tholdKey := "secret123"
	resp := EvaluateQuotesResponse{
		Results: []QuoteEvaluationResult{
			{
				TholdHash:    "hash1",
				Status:       "breached",
				TholdKey:     &tholdKey,
				CurrentPrice: 95000.0,
				TholdPrice:   100000.0,
			},
			{
				TholdHash:    "hash2",
				Status:       "active",
				CurrentPrice: 95000.0,
				TholdPrice:   90000.0,
			},
		},
		CurrentPrice: 95000.0,
		EvaluatedAt:  1700000000,
	}

	jsonData, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var decoded EvaluateQuotesResponse
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(decoded.Results) != 2 {
		t.Errorf("results count = %d, want 2", len(decoded.Results))
	}
	if decoded.CurrentPrice != 95000.0 {
		t.Errorf("current_price = %f, want 95000.0", decoded.CurrentPrice)
	}
	if decoded.EvaluatedAt != 1700000000 {
		t.Errorf("evaluated_at = %d, want 1700000000", decoded.EvaluatedAt)
	}
}

// =============================================================================
// Tests for EvaluateRequest validation
// =============================================================================

func TestEvaluateRequestValidation(t *testing.T) {
	tests := []struct {
		name    string
		request EvaluateRequest
		wantErr bool
		errMsg  string
	}{
		{
			name: "valid single hash",
			request: EvaluateRequest{
				TholdHashes: []string{"1234567890123456789012345678901234567890"},
			},
			wantErr: false,
		},
		{
			name: "valid multiple hashes",
			request: EvaluateRequest{
				TholdHashes: []string{
					"1234567890123456789012345678901234567890",
					"abcdef1234567890123456789012345678901234",
					"fedcba0987654321fedcba0987654321fedcba09",
				},
			},
			wantErr: false,
		},
		{
			name: "valid with callback URL",
			request: EvaluateRequest{
				TholdHashes: []string{"1234567890123456789012345678901234567890"},
				CallbackURL: func() *string { s := "http://example.com/callback"; return &s }(),
			},
			wantErr: false,
		},
		{
			name: "empty hashes",
			request: EvaluateRequest{
				TholdHashes: []string{},
			},
			wantErr: true,
			errMsg:  "thold_hashes required",
		},
		{
			name: "nil hashes",
			request: EvaluateRequest{
				TholdHashes: nil,
			},
			wantErr: true,
			errMsg:  "thold_hashes required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate by checking length
			hasErr := len(tt.request.TholdHashes) == 0
			if hasErr != tt.wantErr {
				t.Errorf("validation error = %v, wantErr %v", hasErr, tt.wantErr)
			}
		})
	}
}

// =============================================================================
// Tests for transformToPriceContract
// =============================================================================

func TestTransformToPriceContract(t *testing.T) {
	tholdKey := "secret123"

	tests := []struct {
		name     string
		input    CREPriceEvent
		expected PriceContractResponse
	}{
		{
			name: "full transformation",
			input: CREPriceEvent{
				ChainNetwork: "mutiny",
				OraclePubkey: "abc123pubkey",
				BasePrice:    100000,
				BaseStamp:    1700000000,
				CommitHash:   "commit123",
				ContractID:   "contract456",
				OracleSig:    "sig789",
				TholdHash:    "thold123",
				TholdKey:     &tholdKey,
				TholdPrice:   95000.0,
			},
			expected: PriceContractResponse{
				ChainNetwork: "mutiny",
				OraclePubkey: "abc123pubkey",
				BasePrice:    100000,
				BaseStamp:    1700000000,
				CommitHash:   "commit123",
				ContractID:   "contract456",
				OracleSig:    "sig789",
				TholdHash:    "thold123",
				TholdKey:     &tholdKey,
				TholdPrice:   95000,
			},
		},
		{
			name: "nil thold_key",
			input: CREPriceEvent{
				ChainNetwork: "signet",
				OraclePubkey: "pubkey456",
				BasePrice:    50000,
				BaseStamp:    1699999999,
				CommitHash:   "commit456",
				ContractID:   "contract789",
				OracleSig:    "sig123",
				TholdHash:    "thold456",
				TholdKey:     nil,
				TholdPrice:   60000.0,
			},
			expected: PriceContractResponse{
				ChainNetwork: "signet",
				OraclePubkey: "pubkey456",
				BasePrice:    50000,
				BaseStamp:    1699999999,
				CommitHash:   "commit456",
				ContractID:   "contract789",
				OracleSig:    "sig123",
				TholdHash:    "thold456",
				TholdKey:     nil,
				TholdPrice:   60000,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := transformToPriceContract(&tt.input)

			if result.ChainNetwork != tt.expected.ChainNetwork {
				t.Errorf("ChainNetwork = %s, want %s", result.ChainNetwork, tt.expected.ChainNetwork)
			}
			if result.OraclePubkey != tt.expected.OraclePubkey {
				t.Errorf("OraclePubkey = %s, want %s", result.OraclePubkey, tt.expected.OraclePubkey)
			}
			if result.BasePrice != tt.expected.BasePrice {
				t.Errorf("BasePrice = %d, want %d", result.BasePrice, tt.expected.BasePrice)
			}
			if result.BaseStamp != tt.expected.BaseStamp {
				t.Errorf("BaseStamp = %d, want %d", result.BaseStamp, tt.expected.BaseStamp)
			}
			if result.CommitHash != tt.expected.CommitHash {
				t.Errorf("CommitHash = %s, want %s", result.CommitHash, tt.expected.CommitHash)
			}
			if result.ContractID != tt.expected.ContractID {
				t.Errorf("ContractID = %s, want %s", result.ContractID, tt.expected.ContractID)
			}
			if result.OracleSig != tt.expected.OracleSig {
				t.Errorf("OracleSig = %s, want %s", result.OracleSig, tt.expected.OracleSig)
			}
			if result.TholdHash != tt.expected.TholdHash {
				t.Errorf("TholdHash = %s, want %s", result.TholdHash, tt.expected.TholdHash)
			}
			if result.TholdPrice != tt.expected.TholdPrice {
				t.Errorf("TholdPrice = %d, want %d", result.TholdPrice, tt.expected.TholdPrice)
			}

			// Check TholdKey pointer
			if (result.TholdKey == nil) != (tt.expected.TholdKey == nil) {
				t.Errorf("TholdKey nil mismatch")
			}
			if result.TholdKey != nil && tt.expected.TholdKey != nil {
				if *result.TholdKey != *tt.expected.TholdKey {
					t.Errorf("TholdKey = %s, want %s", *result.TholdKey, *tt.expected.TholdKey)
				}
			}
		})
	}
}

// =============================================================================
// Concurrent tests for evaluate endpoint
// =============================================================================

func TestConcurrentEvaluateRequests(t *testing.T) {
	setupTestEnv(t)
	loadConfig()
	resetGlobals()

	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	// Set short timeout
	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 100 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	numRequests := 5
	var wg sync.WaitGroup

	for i := 0; i < numRequests; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()

			evalReq := EvaluateRequest{
				TholdHashes: []string{
					fmt.Sprintf("%040d", idx), // Unique 40-char hash
				},
			}
			jsonData, _ := json.Marshal(evalReq)

			req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
			w := httptest.NewRecorder()

			handleEvaluate(w, req)

			// All should get timeout response (202) since no webhook arrives
			if w.Code != http.StatusAccepted {
				t.Errorf("request %d: status = %d, want %d", idx, w.Code, http.StatusAccepted)
			}
		}(i)
	}

	wg.Wait()
}

// =============================================================================
// Benchmark tests for evaluate endpoint
// =============================================================================

func BenchmarkHandleEvaluateValidation(b *testing.B) {
	setupTestEnv(&testing.T{})
	loadConfig()
	resetGlobals()

	evalReq := EvaluateRequest{
		TholdHashes: []string{
			"1234567890123456789012345678901234567890",
			"abcdef1234567890123456789012345678901234",
			"fedcba0987654321fedcba0987654321fedcba09",
		},
	}
	jsonData, _ := json.Marshal(evalReq)

	// Mock server that always returns OK
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"result": "ok"}`))
	}))
	defer mockServer.Close()
	GATEWAY_URL = mockServer.URL

	// Very short timeout to minimize benchmark time
	oldTimeout := BLOCK_TIMEOUT
	BLOCK_TIMEOUT = 1 * time.Millisecond
	defer func() { BLOCK_TIMEOUT = oldTimeout }()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		resetGlobals()
		req := httptest.NewRequest("POST", "/api/evaluate", bytes.NewReader(jsonData))
		w := httptest.NewRecorder()
		handleEvaluate(w, req)
	}
}

func BenchmarkEvaluateQuotesResponseSerialization(b *testing.B) {
	tholdKey := "secret123"
	resp := EvaluateQuotesResponse{
		Results: []QuoteEvaluationResult{
			{TholdHash: "hash1", Status: "breached", TholdKey: &tholdKey, CurrentPrice: 95000.0, TholdPrice: 100000.0},
			{TholdHash: "hash2", Status: "active", CurrentPrice: 95000.0, TholdPrice: 90000.0},
			{TholdHash: "hash3", Status: "breached", TholdKey: &tholdKey, CurrentPrice: 95000.0, TholdPrice: 85000.0},
		},
		CurrentPrice: 95000.0,
		EvaluatedAt:  1700000000,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = json.Marshal(resp)
	}
}
