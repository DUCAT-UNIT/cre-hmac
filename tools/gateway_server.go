package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/crypto/sha3"
)

// Configuration - loaded from environment variables
var (
	WORKFLOW_ID      string
	GATEWAY_URL      string
	AUTHORIZED_KEY   string
	CALLBACK_URL     string
	BLOCK_TIMEOUT    time.Duration
	CLEANUP_INTERVAL time.Duration
	MAX_PENDING      int // Maximum number of pending requests to prevent memory exhaustion
)

// Request tracking
type PendingRequest struct {
	RequestID   string
	CreatedAt   time.Time
	ResultChan  chan *WebhookPayload
	Status      string // "pending", "completed", "timeout"
	Result      *WebhookPayload
	TimedOut    bool
}

var (
	pendingRequests = make(map[string]*PendingRequest)
	requestsMutex   sync.RWMutex
	privateKey      *ecdsa.PrivateKey
	logger          *zap.Logger
)

// Prometheus metrics
var (
	httpRequestsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_http_requests_total",
			Help: "Total number of HTTP requests by endpoint and status",
		},
		[]string{"endpoint", "method", "status"},
	)

	httpRequestDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "gateway_http_request_duration_seconds",
			Help:    "HTTP request latency in seconds",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"endpoint", "method"},
	)

	pendingRequestsGauge = promauto.NewGauge(
		prometheus.GaugeOpts{
			Name: "gateway_pending_requests",
			Help: "Current number of pending requests",
		},
	)

	webhooksReceived = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_webhooks_received_total",
			Help: "Total number of webhooks received by event type",
		},
		[]string{"event_type", "matched"},
	)

	workflowTriggers = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_workflow_triggers_total",
			Help: "Total number of workflow triggers by operation and status",
		},
		[]string{"operation", "status"},
	)

	requestsCleanedUp = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "gateway_requests_cleaned_up_total",
			Help: "Total number of old requests cleaned up",
		},
	)

	requestTimeouts = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_request_timeouts_total",
			Help: "Total number of request timeouts by endpoint",
		},
		[]string{"endpoint"},
	)

	healthChecks = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_health_checks_total",
			Help: "Total number of health/readiness checks by status",
		},
		[]string{"type", "status"},
	)

	dependencyStatus = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "gateway_dependency_status",
			Help: "Status of dependencies (1=up, 0.5=degraded, 0=down)",
		},
		[]string{"dependency"},
	)
)

// Client request types
type CreateRequest struct {
	Th     float64 `json:"th"`
	Domain string  `json:"domain,omitempty"`
}

type CheckRequest struct {
	Domain    string `json:"domain"`
	TholdHash string `json:"thold_hash"`
}

// Webhook payload from CRE
type WebhookPayload struct {
	EventType  string                 `json:"event_type"`
	EventID    string                 `json:"event_id"`
	PubKey     string                 `json:"pubkey"`
	CreatedAt  int64                  `json:"created_at"`
	Kind       int                    `json:"kind"`
	Tags       [][]string             `json:"tags"`
	Content    string                 `json:"content"`
	Sig        string                 `json:"sig"`
	NostrEvent map[string]interface{} `json:"nostr_event"`
}

// PriceContractResponse matches core-ts PriceContract schema exactly
// CRE publishes this format directly to Nostr - no transformation needed
// This is what client-sdk expects from the gateway
type PriceContractResponse struct {
	// PriceObservation fields (from core-ts)
	ChainNetwork string `json:"chain_network"` // Bitcoin network
	OraclePubkey string `json:"oracle_pubkey"` // Server Schnorr public key (32 bytes hex)
	BasePrice    int64  `json:"base_price"`    // Quote creation price
	BaseStamp    int64  `json:"base_stamp"`    // Quote creation timestamp

	// PriceContract fields (from core-ts)
	CommitHash string  `json:"commit_hash"` // hash340(tag, preimage) - 32 bytes hex
	ContractID string  `json:"contract_id"` // hash340(tag, commit||thold) - 32 bytes hex
	OracleSig  string  `json:"oracle_sig"`  // Schnorr signature - 64 bytes hex
	TholdHash  string  `json:"thold_hash"`  // Hash160 commitment - 20 bytes hex
	TholdKey   *string `json:"thold_key"`   // Secret (null if sealed) - 32 bytes hex
	TholdPrice int64   `json:"thold_price"` // Threshold price
}

// Response types
type SyncResponse struct {
	Status    string                 `json:"status"` // "completed", "timeout"
	RequestID string                 `json:"request_id"`
	Data      map[string]interface{} `json:"data,omitempty"`
	Result    *WebhookPayload        `json:"result,omitempty"`
	Message   string                 `json:"message,omitempty"`
}

func init() {
	// Initialize structured logger
	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "info"
	}

	var zapConfig zap.Config
	if os.Getenv("LOG_FORMAT") == "json" {
		zapConfig = zap.NewProductionConfig()
	} else {
		zapConfig = zap.NewDevelopmentConfig()
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
	}

	// Parse log level
	level, err := zapcore.ParseLevel(logLevel)
	if err != nil {
		level = zapcore.InfoLevel
	}
	zapConfig.Level = zap.NewAtomicLevelAt(level)

	logger, err = zapConfig.Build()
	if err != nil {
		log.Fatalf("Failed to initialize logger: %v", err)
	}

	loadConfig()

	// Load private key from environment variable
	privateKeyHex := os.Getenv("DUCAT_PRIVATE_KEY")
	if privateKeyHex == "" {
		logger.Fatal("DUCAT_PRIVATE_KEY environment variable not set")
	}

	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")
	privKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		logger.Fatal("Failed to decode private key", zap.Error(err))
	}

	privateKey, err = crypto.ToECDSA(privKeyBytes)
	if err != nil {
		logger.Fatal("Failed to parse private key", zap.Error(err))
	}

	logger.Info("Gateway server initialized",
		zap.String("authorized_key", AUTHORIZED_KEY),
		zap.String("callback_url", CALLBACK_URL),
		zap.Int("max_pending", MAX_PENDING),
		zap.Duration("block_timeout", BLOCK_TIMEOUT),
		zap.String("workflow_id", WORKFLOW_ID),
	)

	// Start cleanup goroutine
	go cleanupOldRequests()
}

func loadConfig() {
	// Use basic log for config errors since logger might not be initialized yet
	logFatal := func(msg string, args ...interface{}) {
		if logger != nil {
			logger.Fatal(msg)
		} else {
			log.Fatalf(msg, args...)
		}
	}

	logWarn := func(msg string, args ...interface{}) {
		if logger != nil {
			logger.Warn(msg)
		} else {
			log.Printf("⚠️  "+msg, args...)
		}
	}

	// Required configuration
	WORKFLOW_ID = os.Getenv("CRE_WORKFLOW_ID")
	if WORKFLOW_ID == "" {
		logFatal("CRE_WORKFLOW_ID environment variable not set")
	}

	GATEWAY_URL = os.Getenv("CRE_GATEWAY_URL")
	if GATEWAY_URL == "" {
		GATEWAY_URL = "https://01.gateway.zone-a.cre.chain.link" // Default
		logWarn("CRE_GATEWAY_URL not set, using default: " + GATEWAY_URL)
	}

	AUTHORIZED_KEY = os.Getenv("DUCAT_AUTHORIZED_KEY")
	if AUTHORIZED_KEY == "" {
		logFatal("DUCAT_AUTHORIZED_KEY environment variable not set")
	}

	CALLBACK_URL = os.Getenv("GATEWAY_CALLBACK_URL")
	if CALLBACK_URL == "" {
		logFatal("GATEWAY_CALLBACK_URL environment variable not set")
	}

	// Optional configuration with defaults
	blockTimeoutStr := os.Getenv("BLOCK_TIMEOUT_SECONDS")
	if blockTimeoutStr == "" {
		BLOCK_TIMEOUT = 60 * time.Second
	} else {
		var seconds int
		if _, err := fmt.Sscanf(blockTimeoutStr, "%d", &seconds); err != nil {
			logFatal("Invalid BLOCK_TIMEOUT_SECONDS: %v", err)
		}
		BLOCK_TIMEOUT = time.Duration(seconds) * time.Second
	}

	cleanupIntervalStr := os.Getenv("CLEANUP_INTERVAL_SECONDS")
	if cleanupIntervalStr == "" {
		CLEANUP_INTERVAL = 2 * time.Minute // More aggressive cleanup (was 5 minutes)
	} else {
		var seconds int
		if _, err := fmt.Sscanf(cleanupIntervalStr, "%d", &seconds); err != nil {
			logFatal("Invalid CLEANUP_INTERVAL_SECONDS: %v", err)
		}
		CLEANUP_INTERVAL = time.Duration(seconds) * time.Second
	}

	maxPendingStr := os.Getenv("MAX_PENDING_REQUESTS")
	if maxPendingStr == "" {
		MAX_PENDING = 1000 // Default: allow up to 1000 concurrent pending requests
	} else {
		if _, err := fmt.Sscanf(maxPendingStr, "%d", &MAX_PENDING); err != nil {
			logFatal("Invalid MAX_PENDING_REQUESTS: %v", err)
		}
	}
}

func main() {
	defer logger.Sync()

	// Wrap handlers with metrics middleware
	http.Handle("/api/quote", metricsMiddleware("create", http.HandlerFunc(handleCreate)))
	http.Handle("/webhook/ducat", metricsMiddleware("webhook", http.HandlerFunc(handleWebhook)))
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/readiness", handleReadiness)
	http.Handle("/metrics", promhttp.Handler())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	port = ":" + strings.TrimPrefix(port, ":")

	logger.Info("DUCAT Blocking Gateway Server starting",
		zap.String("port", port),
		zap.Duration("block_timeout", BLOCK_TIMEOUT),
		zap.Int("max_pending", MAX_PENDING),
	)

	logger.Info("Endpoints registered",
		zap.Strings("endpoints", []string{
			"GET /api/quote?th=PRICE - Create threshold commitment",
			"POST /webhook/ducat - CRE callback endpoint",
			"GET /health - Liveness probe (simple health check)",
			"GET /readiness - Readiness probe (dependency checks)",
			"GET /metrics - Prometheus metrics",
		}),
	)

	if err := http.ListenAndServe(port, nil); err != nil {
		logger.Fatal("Server failed", zap.Error(err))
	}
}

// metricsMiddleware wraps HTTP handlers with request metrics
func metricsMiddleware(endpoint string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		// Wrap ResponseWriter to capture status code
		rw := &responseWriter{ResponseWriter: w, statusCode: http.StatusOK}

		next.ServeHTTP(rw, r)

		duration := time.Since(start).Seconds()
		status := fmt.Sprintf("%d", rw.statusCode)

		httpRequestsTotal.WithLabelValues(endpoint, r.Method, status).Inc()
		httpRequestDuration.WithLabelValues(endpoint, r.Method).Observe(duration)
	})
}

// responseWriter wraps http.ResponseWriter to capture status code
type responseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

// handleCreate handles GET /api/quote?th=PRICE requests by creating a tracked threshold request,
// triggering the CRE workflow, and blocking until a matching webhook arrives or the server timeout elapses.
//
// It validates the required `th` query parameter (must be a positive number), enqueues a PendingRequest
// (rejecting with 503 if the server is at capacity), and invokes the external workflow. If a matching
// webhook is received before the timeout, the handler returns the webhook's CRE `PriceContractResponse`
// as JSON. If the wait times out, the handler responds with 202 Accepted and a SyncResponse containing
// the request ID for polling via GET /status/{request_id}.
//
// Observed HTTP behaviors:
//  - 200: successful CRE response returned as JSON.
//  - 202: request timed out; polling instruction returned.
//  - 400: missing or invalid `th` parameter.
//  - 405: method not allowed (only GET and OPTIONS supported).
//  - 500: failure to trigger the CRE workflow.
//  - 503: server at capacity (too many pending requests).
func handleCreate(w http.ResponseWriter, r *http.Request) {
	// Set CORS headers
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")

	// Handle preflight
	if r.Method == "OPTIONS" {
		w.WriteHeader(http.StatusOK)
		return
	}

	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse query parameter
	thStr := r.URL.Query().Get("th")
	if thStr == "" {
		http.Error(w, "Missing th query parameter", http.StatusBadRequest)
		return
	}

	// Parse threshold price
	var th float64
	if _, err := fmt.Sscanf(thStr, "%f", &th); err != nil {
		http.Error(w, "Invalid th value", http.StatusBadRequest)
		return
	}

	// Validate request
	if th <= 0 {
		http.Error(w, "Invalid th (threshold price must be positive)", http.StatusBadRequest)
		return
	}

	// Generate domain
	domain := fmt.Sprintf("req-%d", time.Now().UnixNano())

	// Use domain as tracking key (both gateway and CRE know this)
	// CRE will generate its own event_id which we'll receive in the webhook
	trackingKey := domain

	// Create pending request with result channel
	pending := &PendingRequest{
		RequestID:  trackingKey,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Check if we've hit the max pending requests limit
	requestsMutex.Lock()
	currentPending := len(pendingRequests)
	if currentPending >= MAX_PENDING {
		requestsMutex.Unlock()
		logger.Warn("Max pending requests reached, rejecting CREATE request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", MAX_PENDING),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	pendingRequests[trackingKey] = pending
	currentPending = len(pendingRequests)
	requestsMutex.Unlock()

	// Update pending requests gauge
	pendingRequestsGauge.Set(float64(currentPending))

	logger.Info("CREATE request initiated",
		zap.String("domain", domain),
		zap.Float64("threshold_price", th),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", MAX_PENDING),
	)

	// Trigger CRE workflow with configured callback URL
	if err := triggerWorkflow("create", domain, &th, nil, CALLBACK_URL); err != nil {
		logger.Error("Failed to trigger workflow",
			zap.String("domain", domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("create", "error").Inc()

		// Clean up pending request on failure
		requestsMutex.Lock()
		delete(pendingRequests, trackingKey)
		currentPending = len(pendingRequests)
		requestsMutex.Unlock()
		pendingRequestsGauge.Set(float64(currentPending))

		http.Error(w, fmt.Sprintf("Failed to trigger workflow: %v", err), http.StatusInternalServerError)
		return
	}
	workflowTriggers.WithLabelValues("create", "success").Inc()

	// Block waiting for webhook or timeout
	select {
	case result := <-pending.ResultChan:
		// Webhook arrived! Return result immediately
		tholdHash := getTholdHash(result)
		logger.Info("CREATE request completed",
			zap.String("domain", domain),
			zap.String("thold_hash", tholdHash),
			zap.String("event_id", result.EventID),
		)

		requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		requestsMutex.Unlock()

		// Parse CRE response - already in core-ts PriceContract format
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(result.Content), &priceContract); err != nil {
			logger.Warn("Failed to parse webhook content JSON",
				zap.String("domain", domain),
				zap.Error(err),
			)
			// Fall back to raw content on parse error
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"raw": result.Content})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(priceContract)

	case <-time.After(BLOCK_TIMEOUT):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("create").Inc()
		logger.Warn("CREATE request timeout",
			zap.String("domain", domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", BLOCK_TIMEOUT),
		)

		requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		requestsMutex.Unlock()

		response := SyncResponse{
			Status:    "timeout",
			RequestID: trackingKey,
			Message:   "Request is still processing. Use GET /status/" + trackingKey + " to check status.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted
		json.NewEncoder(w).Encode(response)
	}
}

// handleCheck handles POST /check requests by triggering a CRE "check" workflow and blocking until the corresponding webhook arrives or BLOCK_TIMEOUT elapses.
// It validates the JSON body (domain and 40-char thold_hash), registers a PendingRequest keyed by domain (enforcing MAX_PENDING), and invokes the workflow.
// If a matching webhook is received before timeout, the pending request is marked completed and the parsed PriceContractResponse is returned (falls back to raw content on JSON parse failure).
// If BLOCK_TIMEOUT elapses, the pending request is marked timed out and a 202 Accepted SyncResponse containing the request ID is returned for polling.
func handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req CheckRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Validate request
	if req.Domain == "" || len(req.TholdHash) != 40 {
		http.Error(w, "Invalid domain or thold_hash", http.StatusBadRequest)
		return
	}

	// Use domain as tracking key
	trackingKey := req.Domain

	// Create pending request with result channel
	pending := &PendingRequest{
		RequestID:  trackingKey,
		CreatedAt:  time.Now(),
		ResultChan: make(chan *WebhookPayload, 1),
		Status:     "pending",
	}

	// Check if we've hit the max pending requests limit
	requestsMutex.Lock()
	currentPending := len(pendingRequests)
	if currentPending >= MAX_PENDING {
		requestsMutex.Unlock()
		logger.Warn("Max pending requests reached, rejecting CHECK request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", MAX_PENDING),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	pendingRequests[trackingKey] = pending
	currentPending = len(pendingRequests)
	requestsMutex.Unlock()

	logger.Info("CHECK request initiated",
		zap.String("domain", req.Domain),
		zap.String("thold_hash", req.TholdHash),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", MAX_PENDING),
	)

	// Trigger CRE workflow with configured callback URL
	if err := triggerWorkflow("check", req.Domain, nil, &req.TholdHash, CALLBACK_URL); err != nil {
		logger.Error("Failed to trigger workflow",
			zap.String("domain", req.Domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("check", "error").Inc()

		// Clean up pending request on failure
		requestsMutex.Lock()
		delete(pendingRequests, trackingKey)
		currentPending = len(pendingRequests)
		requestsMutex.Unlock()
		pendingRequestsGauge.Set(float64(currentPending))

		http.Error(w, fmt.Sprintf("Failed to trigger workflow: %v", err), http.StatusInternalServerError)
		return
	}
	workflowTriggers.WithLabelValues("check", "success").Inc()

	// Block waiting for webhook or timeout
	select {
	case result := <-pending.ResultChan:
		// Webhook arrived! Return result immediately
		eventType := result.EventType
		if eventType == "breach" {
			logger.Info("BREACH detected - secret revealed",
				zap.String("domain", req.Domain),
			)
		} else {
			logger.Info("CHECK completed",
				zap.String("domain", req.Domain),
				zap.String("status", eventType),
			)
		}

		requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		requestsMutex.Unlock()

		// Parse CRE response - already in core-ts PriceContract format
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(result.Content), &priceContract); err != nil {
			logger.Warn("Failed to parse content JSON",
				zap.String("domain", req.Domain),
				zap.Error(err),
			)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"raw": result.Content})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(priceContract)

	case <-time.After(BLOCK_TIMEOUT):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("check").Inc()
		logger.Warn("CHECK request timeout",
			zap.String("domain", req.Domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", BLOCK_TIMEOUT),
		)

		requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		requestsMutex.Unlock()

		response := SyncResponse{
			Status:    "timeout",
			RequestID: trackingKey,
			Message:   "Request is still processing. Use GET /status/" + trackingKey + " to check status.",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted) // 202 Accepted
		json.NewEncoder(w).Encode(response)
	}
}

// POST /webhook/ducat - Receives callbacks from CRE and unblocks waiting requests
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		logger.Error("Failed to read webhook body", zap.Error(err))
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		logger.Error("Failed to parse webhook JSON", zap.Error(err))
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Extract domain from tags to match pending request
	domain := getTag(payload.Tags, "domain")
	if domain == "" {
		logger.Warn("Webhook missing domain tag, using event_id fallback",
			zap.String("event_id", payload.EventID),
		)
		domain = payload.EventID
	}

	// Find the pending request by domain
	requestsMutex.Lock()
	pending, exists := pendingRequests[domain]
	requestsMutex.Unlock()

	if !exists {
		// This is fine - might be a duplicate webhook from another DON node
		// or a request that already timed out
		webhooksReceived.WithLabelValues(payload.EventType, "no_match").Inc()
		logger.Debug("Webhook received but no pending request found",
			zap.String("domain", domain),
			zap.String("event_id", payload.EventID),
			zap.String("event_type", payload.EventType),
		)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// Send result to the channel (non-blocking)
	select {
	case pending.ResultChan <- &payload:
		webhooksReceived.WithLabelValues(payload.EventType, "matched").Inc()
		logger.Info("Webhook received and matched",
			zap.String("event_type", payload.EventType),
			zap.String("domain", domain),
			zap.String("event_id", payload.EventID),
		)
	default:
		// Channel already has a result or was closed - this is a duplicate webhook
		webhooksReceived.WithLabelValues(payload.EventType, "duplicate").Inc()
		logger.Debug("Duplicate webhook ignored",
			zap.String("domain", domain),
			zap.String("event_id", payload.EventID),
		)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleStatus responds to GET /status/{request_id} with the current state of a tracked request.
// 
// If the request exists and its status is "completed" and the webhook payload can be unmarshaled
// into a PriceContractResponse, the handler returns that PriceContractResponse as JSON.
// Otherwise the handler returns a SyncResponse JSON envelope containing the request's status,
// request ID, and any captured Result; when status is "pending" the response includes a message
// indicating processing is still underway.
// 
// The handler returns HTTP 405 for non-GET methods, 400 when request_id is missing, and 404 when
// the request_id is not found.
func handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := strings.TrimPrefix(r.URL.Path, "/status/")
	if requestID == "" {
		http.Error(w, "Missing request_id", http.StatusBadRequest)
		return
	}

	requestsMutex.RLock()
	pending, exists := pendingRequests[requestID]
	requestsMutex.RUnlock()

	if !exists {
		http.Error(w, "Request not found", http.StatusNotFound)
		return
	}

	// If completed, return PriceContract directly (CRE already outputs correct format)
	if pending.Status == "completed" && pending.Result != nil {
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(pending.Result.Content), &priceContract); err == nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(priceContract)
			return
		}
	}

	// For pending/timeout states, return standard response
	response := SyncResponse{
		Status:    pending.Status,
		RequestID: requestID,
		Result:    pending.Result,
	}

	if pending.Status == "pending" {
		response.Message = "Request is still processing"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

// Health check response
type HealthResponse struct {
	Status       string            `json:"status"`       // "healthy", "degraded", "unhealthy"
	Timestamp    string            `json:"timestamp"`    // ISO 8601 timestamp
	Version      string            `json:"version"`      // Application version
	Uptime       string            `json:"uptime"`       // How long the server has been running
	Dependencies map[string]Health `json:"dependencies"` // Status of dependencies
	Metrics      HealthMetrics     `json:"metrics"`      // Current metrics
}

type Health struct {
	Status      string  `json:"status"`       // "up", "down", "degraded"
	Latency     *string `json:"latency,omitempty"` // Response time if applicable
	Message     string  `json:"message,omitempty"` // Additional info
	LastChecked string  `json:"last_checked"` // When this was last checked
}

type HealthMetrics struct {
	PendingRequests int     `json:"pending_requests"`
	MaxPending      int     `json:"max_pending"`
	CapacityUsed    float64 `json:"capacity_used_percent"`
}

var (
	serverStartTime = time.Now()
	appVersion      = "1.0.0" // Update this with actual version
)

// GET /health - Liveness probe (is the server running?)
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	// Simple liveness check - just verify server is responding
	response := map[string]string{
		"status":    "healthy",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"uptime":    time.Since(serverStartTime).String(),
	}

	healthChecks.WithLabelValues("liveness", "healthy").Inc()

	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// GET /readiness - Readiness probe (is the server ready to accept traffic?)
func handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()

	// Check all dependencies
	deps := make(map[string]Health)
	overallStatus := "healthy"

	// 1. Check CRE Gateway reachability
	creHealth := checkCREGateway(ctx)
	deps["cre_gateway"] = creHealth
	if creHealth.Status != "up" {
		overallStatus = "degraded"
	}

	// 2. Check capacity
	requestsMutex.RLock()
	currentPending := len(pendingRequests)
	requestsMutex.RUnlock()

	capacityPercent := float64(currentPending) / float64(MAX_PENDING) * 100
	capacityStatus := "up"
	capacityMessage := "Capacity available"

	if capacityPercent >= 90 {
		capacityStatus = "degraded"
		capacityMessage = "Near capacity limit"
		overallStatus = "degraded"
	} else if capacityPercent >= 100 {
		capacityStatus = "down"
		capacityMessage = "At capacity limit"
		overallStatus = "unhealthy"
	}

	deps["capacity"] = Health{
		Status:      capacityStatus,
		Message:     capacityMessage,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}

	// 3. Check if private key is loaded
	if privateKey == nil {
		deps["authentication"] = Health{
			Status:      "down",
			Message:     "Private key not loaded",
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
		overallStatus = "unhealthy"
	} else {
		deps["authentication"] = Health{
			Status:      "up",
			Message:     "Private key loaded",
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}

	// Build response
	response := HealthResponse{
		Status:    overallStatus,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
		Version:   appVersion,
		Uptime:    time.Since(serverStartTime).String(),
		Dependencies: deps,
		Metrics: HealthMetrics{
			PendingRequests: currentPending,
			MaxPending:      MAX_PENDING,
			CapacityUsed:    capacityPercent,
		},
	}

	// Set appropriate status code
	statusCode := http.StatusOK
	if overallStatus == "degraded" {
		statusCode = http.StatusOK // Still ready, but degraded
	} else if overallStatus == "unhealthy" {
		statusCode = http.StatusServiceUnavailable
	}

	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)

	// Record metrics
	healthChecks.WithLabelValues("readiness", overallStatus).Inc()

	// Update dependency status metrics
	for depName, depHealth := range deps {
		var statusValue float64
		switch depHealth.Status {
		case "up":
			statusValue = 1.0
		case "degraded":
			statusValue = 0.5
		case "down":
			statusValue = 0.0
		}
		dependencyStatus.WithLabelValues(depName).Set(statusValue)
	}

	// Log readiness check failures
	if overallStatus != "healthy" {
		logger.Warn("Readiness check failed",
			zap.String("status", overallStatus),
			zap.Any("dependencies", deps),
		)
	}
}

// checkCREGateway verifies connectivity to the CRE gateway
func checkCREGateway(ctx context.Context) Health {
	start := time.Now()

	// Create a HEAD request with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, "HEAD", GATEWAY_URL, nil)
	if err != nil {
		return Health{
			Status:      "down",
			Message:     fmt.Sprintf("Failed to create request: %v", err),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Do(req)
	latency := time.Since(start)
	latencyStr := latency.String()

	if err != nil {
		logger.Warn("CRE gateway health check failed",
			zap.Error(err),
			zap.String("gateway_url", GATEWAY_URL),
		)
		return Health{
			Status:      "down",
			Message:     fmt.Sprintf("Unreachable: %v", err),
			LastChecked: time.Now().UTC().Format(time.RFC3339),
		}
	}
	defer resp.Body.Close()

	// Consider any response (even 404) as "up" - we just care if it's reachable
	status := "up"
	message := "Reachable"

	if latency > 2*time.Second {
		status = "degraded"
		message = "Slow response time"
	}

	return Health{
		Status:      status,
		Latency:     &latencyStr,
		Message:     message,
		LastChecked: time.Now().UTC().Format(time.RFC3339),
	}
}

// triggerWorkflow sends HTTP trigger to CRE gateway using proper JWT format
func triggerWorkflow(op, domain string, tholdPrice *float64, tholdHash *string, callbackURL string) error {
	// Build input
	input := map[string]interface{}{
		"domain":       domain,
		"callback_url": callbackURL,
	}

	if tholdPrice != nil {
		input["thold_price"] = *tholdPrice
	}
	if tholdHash != nil {
		input["thold_hash"] = *tholdHash
	}

	// Create JSON-RPC request
	reqID := fmt.Sprintf("%d", time.Now().UnixNano())
	rpcRequest := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      reqID,
		"method":  "workflows.execute",
		"params": map[string]interface{}{
			"input": input,
			"workflow": map[string]interface{}{
				"workflowID": WORKFLOW_ID,
			},
		},
	}

	rpcJSON, err := json.Marshal(rpcRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	// Compute SHA256 digest of the request
	digest := sha256.Sum256(rpcJSON)
	digestHex := "0x" + hex.EncodeToString(digest[:])

	// Generate JWT token
	token, err := generateJWT(privateKey, AUTHORIZED_KEY, digestHex)
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Send request
	req, err := http.NewRequest("POST", GATEWAY_URL, bytes.NewReader(rpcJSON))
	if err != nil {
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return fmt.Errorf("non-success status %d: %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// generateJWT creates a proper JWT token with header.payload.signature format
func generateJWT(privKey *ecdsa.PrivateKey, address, digest string) (string, error) {
	now := time.Now().Unix()

	// Create header (base64url encoded)
	header := map[string]interface{}{
		"alg": "ETH",
		"typ": "JWT",
	}
	headerJSON, _ := json.Marshal(header)
	headerB64 := encodeBase64URL(headerJSON)

	// Create payload (base64url encoded)
	payload := map[string]interface{}{
		"digest": digest,
		"iss":    address,
		"iat":    now,
		"exp":    now + 300, // 5 minutes
		"jti":    generateRequestID(),
	}
	payloadJSON, _ := json.Marshal(payload)
	payloadB64 := encodeBase64URL(payloadJSON)

	// Message to sign: header.payload
	message := headerB64 + "." + payloadB64

	// Sign the message
	signature, err := signEthereumMessage(privKey, message)
	if err != nil {
		return "", fmt.Errorf("failed to sign JWT: %w", err)
	}

	// Encode signature as base64url
	signatureB64 := encodeBase64URL(signature)

	// Final JWT: header.payload.signature
	return message + "." + signatureB64, nil
}

// Ethereum message signing (same as trigger-http tool)
func signEthereumMessage(privKey *ecdsa.PrivateKey, message string) ([]byte, error) {
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)

	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Sign using standard ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash)
	if err != nil {
		return nil, fmt.Errorf("signing failed: %w", err)
	}

	// Normalize s to lower value (BIP-62)
	halfOrder := new(big.Int).Div(btcec.S256().N, big.NewInt(2))
	if s.Cmp(halfOrder) > 0 {
		s.Sub(btcec.S256().N, s)
	}

	// Convert to btcec for recovery ID computation
	privKeyBytes := crypto.FromECDSA(privKey)
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	// Convert r, s to btcec.ModNScalar
	var rScalar, sScalar btcec.ModNScalar
	rScalar.SetByteSlice(r.Bytes())
	sScalar.SetByteSlice(s.Bytes())

	recoveryID, err := computeRecoveryID(btcPrivKey, btcPubKey, messageHash, &rScalar, &sScalar)
	if err != nil {
		return nil, fmt.Errorf("recovery ID computation failed: %w", err)
	}

	// Format: r || s || v
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	result := make([]byte, 65)
	copy(result[0:32], rPadded)
	copy(result[32:64], sPadded)
	result[64] = recoveryID

	return result, nil
}

func computeRecoveryID(privKey *btcec.PrivateKey, pubKey *btcec.PublicKey, messageHash []byte, r, s *btcec.ModNScalar) (byte, error) {
	expectedBytes := pubKey.SerializeUncompressed()
	for recoveryID := byte(0); recoveryID < 4; recoveryID++ {
		recoveredPubKey := tryRecoverPublicKey(messageHash, r, s, recoveryID)
		if recoveredPubKey != nil {
			recoveredBytes := recoveredPubKey.SerializeUncompressed()
			if bytes.Equal(recoveredBytes, expectedBytes) {
				return recoveryID, nil
			}
		}
	}
	return 0, fmt.Errorf("failed to compute recovery ID: no valid recovery ID (0-3) matched for pubkey=%x",
		expectedBytes[:8])
}

func tryRecoverPublicKey(messageHash []byte, r, s *btcec.ModNScalar, recoveryID byte) *btcec.PublicKey {
	curve := btcec.S256()
	rBytes := r.Bytes()
	sBytes := s.Bytes()

	rBig := new(big.Int).SetBytes(rBytes[:])
	sBig := new(big.Int).SetBytes(sBytes[:])

	if recoveryID&2 == 2 {
		rBig.Add(rBig, curve.N)
	}

	if rBig.Cmp(curve.P) >= 0 {
		return nil
	}

	ySquared := new(big.Int).Exp(rBig, big.NewInt(3), curve.P)
	ySquared.Add(ySquared, curve.B)
	ySquared.Mod(ySquared, curve.P)

	y := new(big.Int).ModSqrt(ySquared, curve.P)
	if y == nil {
		return nil
	}

	if (recoveryID&1 == 1 && y.Bit(0) == 0) || (recoveryID&1 == 0 && y.Bit(0) == 1) {
		y.Sub(curve.P, y)
	}

	var xFieldVal, yFieldVal btcec.FieldVal
	xFieldVal.SetByteSlice(rBig.Bytes())
	yFieldVal.SetByteSlice(y.Bytes())
	R := btcec.NewPublicKey(&xFieldVal, &yFieldVal)

	e := new(big.Int).SetBytes(messageHash)
	rInv := new(big.Int).ModInverse(rBig, curve.N)

	sR_x, sR_y := curve.ScalarMult(R.X(), R.Y(), sBig.Bytes())
	eNeg := new(big.Int).Neg(e)
	eNeg.Mod(eNeg, curve.N)
	eG_x, eG_y := curve.ScalarBaseMult(eNeg.Bytes())

	qX, qY := curve.Add(sR_x, sR_y, eG_x, eG_y)
	qX, qY = curve.ScalarMult(qX, qY, rInv.Bytes())

	var qXFieldVal, qYFieldVal btcec.FieldVal
	qXFieldVal.SetByteSlice(qX.Bytes())
	qYFieldVal.SetByteSlice(qY.Bytes())

	return btcec.NewPublicKey(&qXFieldVal, &qYFieldVal)
}

func encodeBase64URL(data []byte) string {
	encoded := make([]byte, len(data)*4/3+4)
	n := 0
	for i := 0; i < len(data); i += 3 {
		remaining := len(data) - i
		if remaining >= 3 {
			chunk := uint32(data[i])<<16 | uint32(data[i+1])<<8 | uint32(data[i+2])
			encoded[n] = base64URLChars[(chunk>>18)&0x3F]
			encoded[n+1] = base64URLChars[(chunk>>12)&0x3F]
			encoded[n+2] = base64URLChars[(chunk>>6)&0x3F]
			encoded[n+3] = base64URLChars[chunk&0x3F]
			n += 4
		} else if remaining == 2 {
			chunk := uint32(data[i])<<16 | uint32(data[i+1])<<8
			encoded[n] = base64URLChars[(chunk>>18)&0x3F]
			encoded[n+1] = base64URLChars[(chunk>>12)&0x3F]
			encoded[n+2] = base64URLChars[(chunk>>6)&0x3F]
			n += 3
		} else {
			chunk := uint32(data[i]) << 16
			encoded[n] = base64URLChars[(chunk>>18)&0x3F]
			encoded[n+1] = base64URLChars[(chunk>>12)&0x3F]
			n += 2
		}
	}
	return string(encoded[:n])
}

const base64URLChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

func generateRequestID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// getTag extracts the value for a given key from a Nostr-style tags slice.
// It returns the second element of the first tag whose first element equals key, or an empty string if no match is found.
func getTag(tags [][]string, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

// getTholdHash extracts the TholdHash field from the WebhookPayload's Content interpreted as a PriceContractResponse.
// If the payload content cannot be parsed as a PriceContractResponse, it returns the empty string.
func getTholdHash(payload *WebhookPayload) string {
	var priceContract PriceContractResponse
	json.Unmarshal([]byte(payload.Content), &priceContract)
	return priceContract.TholdHash
}

// Cleanup old completed/timed-out requests to prevent memory leak
func cleanupOldRequests() {
	ticker := time.NewTicker(CLEANUP_INTERVAL)
	defer ticker.Stop()

	for range ticker.C {
		requestsMutex.Lock()
		now := time.Now()
		cleaned := 0

		for id, req := range pendingRequests {
			// More aggressive cleanup strategy:
			// 1. Remove completed requests older than 5 minutes
			// 2. Remove timed-out requests older than 5 minutes (they should poll /status)
			// 3. Remove any stale pending requests older than 2x BLOCK_TIMEOUT
			shouldDelete := false

			if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
				shouldDelete = true
			} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
				shouldDelete = true
			} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*BLOCK_TIMEOUT {
				// Stale pending request that never completed or timed out (shouldn't happen)
				age := now.Sub(req.CreatedAt)
				logger.Warn("Cleaning up stale pending request",
					zap.String("request_id", id),
					zap.Duration("age", age),
					zap.String("status", req.Status),
				)
				shouldDelete = true
			}

			if shouldDelete {
				delete(pendingRequests, id)
				cleaned++
			}
		}

		currentPending := len(pendingRequests)
		requestsMutex.Unlock()

		if cleaned > 0 {
			requestsCleanedUp.Add(float64(cleaned))
			logger.Info("Cleanup completed",
				zap.Int("removed", cleaned),
				zap.Int("pending", currentPending),
				zap.Int("max_pending", MAX_PENDING),
			)
		}

		// Update gauge after cleanup
		pendingRequestsGauge.Set(float64(currentPending))
	}
}