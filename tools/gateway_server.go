package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"ducat/internal/ethsign"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"golang.org/x/time/rate"
)

// GatewayConfig holds all gateway server configuration
type GatewayConfig struct {
	WorkflowID      string
	GatewayURL      string
	AuthorizedKey   string
	CallbackURL     string
	BlockTimeout    time.Duration
	CleanupInterval time.Duration
	MaxPending      int

	// Rate limiting configuration
	WebhookRateLimit  rate.Limit // requests per second
	WebhookBurstLimit int        // burst capacity
}

// GatewayServer encapsulates all server state
type GatewayServer struct {
	config          *GatewayConfig
	privateKey      *ecdsa.PrivateKey
	logger          *zap.Logger
	pendingRequests map[string]*PendingRequest
	requestsMutex   sync.RWMutex
	shutdownChan    chan struct{}
	webhookLimiter  *rate.Limiter
}

// Request tracking
type PendingRequest struct {
	RequestID  string
	CreatedAt  time.Time
	ResultChan chan *WebhookPayload
	Status     string // "pending", "completed", "timeout"
	Result     *WebhookPayload
	TimedOut   bool
}

// Global server instance (initialized in init)
var (
	server *GatewayServer
	logger *zap.Logger
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

	rateLimitRejected = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "gateway_rate_limit_rejected_total",
			Help: "Total number of requests rejected due to rate limiting",
		},
		[]string{"endpoint"},
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

	// Load configuration into struct
	config := loadConfig()

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

	privateKey, err := crypto.ToECDSA(privKeyBytes)
	if err != nil {
		logger.Fatal("Failed to parse private key", zap.Error(err))
	}

	// Initialize server with config
	server = &GatewayServer{
		config:          config,
		privateKey:      privateKey,
		logger:          logger,
		pendingRequests: make(map[string]*PendingRequest),
		shutdownChan:    make(chan struct{}),
		webhookLimiter:  rate.NewLimiter(config.WebhookRateLimit, config.WebhookBurstLimit),
	}

	logger.Info("Gateway server initialized",
		zap.String("authorized_key", config.AuthorizedKey),
		zap.String("callback_url", config.CallbackURL),
		zap.Int("max_pending", config.MaxPending),
		zap.Duration("block_timeout", config.BlockTimeout),
		zap.String("workflow_id", config.WorkflowID),
		zap.Float64("webhook_rate_limit", float64(config.WebhookRateLimit)),
		zap.Int("webhook_burst_limit", config.WebhookBurstLimit),
	)

	// Start cleanup goroutine
	go server.cleanupOldRequests()
}

func loadConfig() *GatewayConfig {
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

	config := &GatewayConfig{}

	// Required configuration
	config.WorkflowID = os.Getenv("CRE_WORKFLOW_ID")
	if config.WorkflowID == "" {
		logFatal("CRE_WORKFLOW_ID environment variable not set")
	}

	config.GatewayURL = os.Getenv("CRE_GATEWAY_URL")
	if config.GatewayURL == "" {
		config.GatewayURL = "https://01.gateway.zone-a.cre.chain.link" // Default
		logWarn("CRE_GATEWAY_URL not set, using default: " + config.GatewayURL)
	}

	config.AuthorizedKey = os.Getenv("DUCAT_AUTHORIZED_KEY")
	if config.AuthorizedKey == "" {
		logFatal("DUCAT_AUTHORIZED_KEY environment variable not set")
	}

	config.CallbackURL = os.Getenv("GATEWAY_CALLBACK_URL")
	if config.CallbackURL == "" {
		logFatal("GATEWAY_CALLBACK_URL environment variable not set")
	}

	// Optional configuration with defaults
	blockTimeoutStr := os.Getenv("BLOCK_TIMEOUT_SECONDS")
	if blockTimeoutStr == "" {
		config.BlockTimeout = 60 * time.Second
	} else {
		var seconds int
		if _, err := fmt.Sscanf(blockTimeoutStr, "%d", &seconds); err != nil {
			logFatal("Invalid BLOCK_TIMEOUT_SECONDS: %v", err)
		}
		config.BlockTimeout = time.Duration(seconds) * time.Second
	}

	cleanupIntervalStr := os.Getenv("CLEANUP_INTERVAL_SECONDS")
	if cleanupIntervalStr == "" {
		config.CleanupInterval = 2 * time.Minute
	} else {
		var seconds int
		if _, err := fmt.Sscanf(cleanupIntervalStr, "%d", &seconds); err != nil {
			logFatal("Invalid CLEANUP_INTERVAL_SECONDS: %v", err)
		}
		config.CleanupInterval = time.Duration(seconds) * time.Second
	}

	maxPendingStr := os.Getenv("MAX_PENDING_REQUESTS")
	if maxPendingStr == "" {
		config.MaxPending = 1000
	} else {
		if _, err := fmt.Sscanf(maxPendingStr, "%d", &config.MaxPending); err != nil {
			logFatal("Invalid MAX_PENDING_REQUESTS: %v", err)
		}
	}

	// Rate limiting configuration
	// Default: 100 requests/second with burst of 200
	webhookRateLimitStr := os.Getenv("WEBHOOK_RATE_LIMIT")
	if webhookRateLimitStr == "" {
		config.WebhookRateLimit = 100
	} else {
		var rateLimit float64
		if _, err := fmt.Sscanf(webhookRateLimitStr, "%f", &rateLimit); err != nil {
			logFatal("Invalid WEBHOOK_RATE_LIMIT: %v", err)
		}
		config.WebhookRateLimit = rate.Limit(rateLimit)
	}

	webhookBurstStr := os.Getenv("WEBHOOK_BURST_LIMIT")
	if webhookBurstStr == "" {
		config.WebhookBurstLimit = 200
	} else {
		if _, err := fmt.Sscanf(webhookBurstStr, "%d", &config.WebhookBurstLimit); err != nil {
			logFatal("Invalid WEBHOOK_BURST_LIMIT: %v", err)
		}
	}

	return config
}

func main() {
	defer logger.Sync()

	// Wrap handlers with metrics middleware
	http.Handle("/api/quote", metricsMiddleware("create", http.HandlerFunc(server.handleCreate)))
	http.Handle("/webhook/ducat", metricsMiddleware("webhook", server.rateLimitMiddleware(http.HandlerFunc(server.handleWebhook))))
	http.HandleFunc("/health", handleHealth)
	http.HandleFunc("/readiness", server.handleReadiness)
	http.Handle("/metrics", promhttp.Handler())

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	port = ":" + strings.TrimPrefix(port, ":")

	logger.Info("DUCAT Blocking Gateway Server starting",
		zap.String("port", port),
		zap.Duration("block_timeout", server.config.BlockTimeout),
		zap.Int("max_pending", server.config.MaxPending),
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

	// Create HTTP server for graceful shutdown
	httpServer := &http.Server{
		Addr:         port,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: server.config.BlockTimeout + 10*time.Second, // Allow for blocking requests
		IdleTimeout:  120 * time.Second,
	}

	// Channel to signal server shutdown complete
	serverDone := make(chan struct{})

	// Start server in goroutine
	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal("Server failed", zap.Error(err))
		}
		close(serverDone)
	}()

	// Wait for interrupt signal for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigChan

	logger.Info("Received shutdown signal", zap.String("signal", sig.String()))

	// Signal cleanup goroutine to stop
	close(server.shutdownChan)

	// Create shutdown context with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Gracefully shutdown HTTP server
	if err := httpServer.Shutdown(shutdownCtx); err != nil {
		logger.Error("Server shutdown error", zap.Error(err))
	}

	// Wait for server to finish
	<-serverDone

	logger.Info("Server shutdown complete")
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

// rateLimitMiddleware applies token bucket rate limiting to protect against DoS attacks.
// Returns 429 Too Many Requests if the rate limit is exceeded.
func (s *GatewayServer) rateLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.webhookLimiter.Allow() {
			rateLimitRejected.WithLabelValues("webhook").Inc()
			s.logger.Warn("Rate limit exceeded",
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("endpoint", r.URL.Path),
			)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
		next.ServeHTTP(w, r)
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
func (s *GatewayServer) handleCreate(w http.ResponseWriter, r *http.Request) {
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
	s.requestsMutex.Lock()
	currentPending := len(s.pendingRequests)
	if currentPending >= s.config.MaxPending {
		s.requestsMutex.Unlock()
		s.logger.Warn("Max pending requests reached, rejecting CREATE request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", s.config.MaxPending),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	s.pendingRequests[trackingKey] = pending
	currentPending = len(s.pendingRequests)
	s.requestsMutex.Unlock()

	// Update pending requests gauge
	pendingRequestsGauge.Set(float64(currentPending))

	s.logger.Info("CREATE request initiated",
		zap.String("domain", domain),
		zap.Float64("threshold_price", th),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", s.config.MaxPending),
	)

	// Trigger CRE workflow with configured callback URL
	if err := s.triggerWorkflow("create", domain, &th, nil, s.config.CallbackURL); err != nil {
		s.logger.Error("Failed to trigger workflow",
			zap.String("domain", domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("create", "error").Inc()

		// Clean up pending request on failure
		s.requestsMutex.Lock()
		delete(s.pendingRequests, trackingKey)
		currentPending = len(s.pendingRequests)
		s.requestsMutex.Unlock()
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
		s.logger.Info("CREATE request completed",
			zap.String("domain", domain),
			zap.String("thold_hash", tholdHash),
			zap.String("event_id", result.EventID),
		)

		s.requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		s.requestsMutex.Unlock()

		// Parse CRE response - already in core-ts PriceContract format
		var priceContract PriceContractResponse
		if err := json.Unmarshal([]byte(result.Content), &priceContract); err != nil {
			s.logger.Warn("Failed to parse webhook content JSON",
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

	case <-time.After(s.config.BlockTimeout):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("create").Inc()
		s.logger.Warn("CREATE request timeout",
			zap.String("domain", domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", s.config.BlockTimeout),
		)

		s.requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		s.requestsMutex.Unlock()

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

// handleCheck handles POST /check requests by triggering a CRE "check" workflow and blocking until the corresponding webhook arrives or s.config.BlockTimeout elapses.
// It validates the JSON body (domain and 40-char thold_hash), registers a PendingRequest keyed by domain (enforcing s.config.MaxPending), and invokes the workflow.
// If a matching webhook is received before timeout, the pending request is marked completed and the parsed PriceContractResponse is returned (falls back to raw content on JSON parse failure).
// If s.config.BlockTimeout elapses, the pending request is marked timed out and a 202 Accepted SyncResponse containing the request ID is returned for polling.
func (s *GatewayServer) handleCheck(w http.ResponseWriter, r *http.Request) {
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
	s.requestsMutex.Lock()
	currentPending := len(s.pendingRequests)
	if currentPending >= s.config.MaxPending {
		s.requestsMutex.Unlock()
		logger.Warn("Max pending requests reached, rejecting CHECK request",
			zap.Int("current_pending", currentPending),
			zap.Int("max_pending", s.config.MaxPending),
		)
		http.Error(w, "Server at capacity, please retry later", http.StatusServiceUnavailable)
		return
	}
	s.pendingRequests[trackingKey] = pending
	currentPending = len(s.pendingRequests)
	s.requestsMutex.Unlock()

	logger.Info("CHECK request initiated",
		zap.String("domain", req.Domain),
		zap.String("thold_hash", req.TholdHash),
		zap.String("tracking_key", trackingKey),
		zap.Int("pending_count", currentPending),
		zap.Int("max_pending", s.config.MaxPending),
	)

	// Trigger CRE workflow with configured callback URL
	if err := s.triggerWorkflow("check", req.Domain, nil, &req.TholdHash, s.config.CallbackURL); err != nil {
		logger.Error("Failed to trigger workflow",
			zap.String("domain", req.Domain),
			zap.Error(err),
		)
		workflowTriggers.WithLabelValues("check", "error").Inc()

		// Clean up pending request on failure
		s.requestsMutex.Lock()
		delete(s.pendingRequests, trackingKey)
		currentPending = len(s.pendingRequests)
		s.requestsMutex.Unlock()
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

		s.requestsMutex.Lock()
		pending.Status = "completed"
		pending.Result = result
		s.requestsMutex.Unlock()

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

	case <-time.After(s.config.BlockTimeout):
		// Timeout - return 202 with request_id for polling
		requestTimeouts.WithLabelValues("check").Inc()
		logger.Warn("CHECK request timeout",
			zap.String("domain", req.Domain),
			zap.String("request_id", trackingKey),
			zap.Duration("timeout", s.config.BlockTimeout),
		)

		s.requestsMutex.Lock()
		pending.Status = "timeout"
		pending.TimedOut = true
		s.requestsMutex.Unlock()

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

// handleWebhook receives POST callbacks from the CRE workflow and unblocks waiting requests.
//
// Webhook Domain Resolution:
// The handler extracts the tracking domain from the webhook payload's tags. If no "domain" tag
// is present, it falls back to using the event_id as the domain key. This fallback ensures
// backward compatibility with CRE workflows that may not include explicit domain tags.
//
// Note for CRE Integration:
// CRE workflows should include a "domain" tag in their Nostr event to ensure proper request
// matching. The domain should match the request_id generated by handleCreate/handleCheck.
// Example: Tags: [["d", commit_hash], ["domain", request_id]]
func (s *GatewayServer) handleWebhook(w http.ResponseWriter, r *http.Request) {
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
	s.requestsMutex.Lock()
	pending, exists := s.pendingRequests[domain]
	s.requestsMutex.Unlock()

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
func (s *GatewayServer) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	requestID := strings.TrimPrefix(r.URL.Path, "/status/")
	if requestID == "" {
		http.Error(w, "Missing request_id", http.StatusBadRequest)
		return
	}

	s.requestsMutex.RLock()
	pending, exists := s.pendingRequests[requestID]
	s.requestsMutex.RUnlock()

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
func (s *GatewayServer) handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")

	ctx := r.Context()

	// Check all dependencies
	deps := make(map[string]Health)
	overallStatus := "healthy"

	// 1. Check CRE Gateway reachability
	creHealth := s.checkCREGateway(ctx)
	deps["cre_gateway"] = creHealth
	if creHealth.Status != "up" {
		overallStatus = "degraded"
	}

	// 2. Check capacity
	s.requestsMutex.RLock()
	currentPending := len(s.pendingRequests)
	s.requestsMutex.RUnlock()

	capacityPercent := float64(currentPending) / float64(s.config.MaxPending) * 100
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
	if s.privateKey == nil {
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
			MaxPending:      s.config.MaxPending,
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
func (s *GatewayServer) checkCREGateway(ctx context.Context) Health {
	start := time.Now()

	// Create a HEAD request with timeout
	checkCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(checkCtx, "HEAD", s.config.GatewayURL, nil)
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
			zap.String("gateway_url", s.config.GatewayURL),
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
func (s *GatewayServer) triggerWorkflow(op, domain string, tholdPrice *float64, tholdHash *string, callbackURL string) error {
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
				"workflowID": s.config.WorkflowID,
			},
		},
	}

	// Use deterministic JSON marshaling for consistent digest computation
	// This ensures the same request always produces the same signature
	rpcJSON, err := marshalSorted(rpcRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal RPC request: %w", err)
	}

	// Compute SHA256 digest of the request
	digest := sha256.Sum256(rpcJSON)
	digestHex := "0x" + hex.EncodeToString(digest[:])

	// Generate JWT token using shared ethsign package
	token, err := ethsign.GenerateJWT(s.privateKey, s.config.AuthorizedKey, digestHex, ethsign.GenerateRequestID())
	if err != nil {
		return fmt.Errorf("failed to generate JWT: %w", err)
	}

	// Send request
	req, err := http.NewRequest("POST", s.config.GatewayURL, bytes.NewReader(rpcJSON))
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

// marshalSorted marshals v to JSON with all map keys sorted lexicographically at every level.
// This ensures deterministic output for consistent digest computation across requests.
func marshalSorted(v interface{}) ([]byte, error) {
	// Convert to map structure first via standard JSON round-trip
	temp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var data interface{}
	if err := json.Unmarshal(temp, &data); err != nil {
		return nil, err
	}

	// Custom marshal with sorted keys
	var buf bytes.Buffer
	if err := marshalSortedRecursive(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// marshalSortedRecursive writes the JSON encoding of v to buf with all map keys
// sorted lexicographically at every level.
func marshalSortedRecursive(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			keyBytes, _ := json.Marshal(k)
			buf.Write(keyBytes)
			buf.WriteString(":")
			if err := marshalSortedRecursive(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	case []interface{}:
		buf.WriteString("[")
		for i, item := range val {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := marshalSortedRecursive(buf, item); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	default:
		b, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(b)
	}
	return nil
}

// cleanupOldRequests periodically removes stale requests to prevent memory leaks.
// It respects the shutdownChan for graceful termination during server shutdown.
//
// Cleanup strategy:
//   - Remove completed requests older than 5 minutes
//   - Remove timed-out requests older than 5 minutes (clients should poll /status)
//   - Remove stale pending requests older than 2x s.config.BlockTimeout (edge case handling)
func (s *GatewayServer) cleanupOldRequests() {
	ticker := time.NewTicker(s.config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.shutdownChan:
			logger.Info("Cleanup goroutine received shutdown signal")
			return
		case <-ticker.C:
			s.requestsMutex.Lock()
			now := time.Now()
			cleaned := 0

			for id, req := range s.pendingRequests {
				shouldDelete := false

				if req.Status == "completed" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "timeout" && now.Sub(req.CreatedAt) > 5*time.Minute {
					shouldDelete = true
				} else if req.Status == "pending" && now.Sub(req.CreatedAt) > 2*s.config.BlockTimeout {
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
					delete(s.pendingRequests, id)
					cleaned++
				}
			}

			currentPending := len(s.pendingRequests)
			s.requestsMutex.Unlock()

			if cleaned > 0 {
				requestsCleanedUp.Add(float64(cleaned))
				logger.Info("Cleanup completed",
					zap.Int("removed", cleaned),
					zap.Int("pending", currentPending),
					zap.Int("max_pending", s.config.MaxPending),
				)
			}

			// Update gauge after cleanup
			pendingRequestsGauge.Set(float64(currentPending))
		}
	}
}