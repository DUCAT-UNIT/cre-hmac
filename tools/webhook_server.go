package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// EventTTL is how long to remember processed event IDs (prevents duplicates)
	EventTTL = 1 * time.Hour
	// CleanupInterval is how often to run the cleanup goroutine
	CleanupInterval = 5 * time.Minute
	// MaxCacheSize is the maximum number of entries before forced cleanup
	MaxCacheSize = 10000
)

// TTLCache provides a bounded, thread-safe cache with automatic expiration
type TTLCache struct {
	mu      sync.RWMutex
	entries map[string]time.Time
	ttl     time.Duration
	maxSize int
}

// NewTTLCache creates a TTLCache with the specified entry TTL, maximum size, and cleanup interval.
// ttl is the duration each entry remains valid; maxSize is the maximum number of entries the cache will hold;
// cleanupInterval controls how frequently a background goroutine removes expired entries.
func NewTTLCache(ttl time.Duration, maxSize int, cleanupInterval time.Duration) *TTLCache {
	cache := &TTLCache{
		entries: make(map[string]time.Time),
		ttl:     ttl,
		maxSize: maxSize,
	}
	go cache.cleanupLoop(cleanupInterval)
	return cache
}

// Contains checks if the key exists and is not expired
func (c *TTLCache) Contains(key string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()

	expiry, exists := c.entries[key]
	if !exists {
		return false
	}
	return time.Now().Before(expiry)
}

// Add adds a key to the cache with the configured TTL
// Returns true if the key was newly added, false if it already existed
func (c *TTLCache) Add(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if already exists and not expired
	if expiry, exists := c.entries[key]; exists && time.Now().Before(expiry) {
		return false
	}

	// If at max capacity, do a synchronous cleanup
	if len(c.entries) >= c.maxSize {
		c.cleanupExpiredLocked()
	}

	c.entries[key] = time.Now().Add(c.ttl)
	return true
}

// cleanupLoop periodically removes expired entries
func (c *TTLCache) cleanupLoop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		c.mu.Lock()
		c.cleanupExpiredLocked()
		c.mu.Unlock()
	}
}

// cleanupExpiredLocked removes expired entries (must be called with lock held)
func (c *TTLCache) cleanupExpiredLocked() {
	now := time.Now()
	for key, expiry := range c.entries {
		if now.After(expiry) {
			delete(c.entries, key)
		}
	}
}

// Size returns the current number of entries in the cache
func (c *TTLCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Idempotency tracking - bounded TTL cache for processed event IDs
var processedEvents = NewTTLCache(EventTTL, MaxCacheSize, CleanupInterval)

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

type PriceEvent struct {
	EventOrigin  interface{} `json:"event_origin"`
	EventPrice   interface{} `json:"event_price"`
	EventStamp   interface{} `json:"event_stamp"`
	EventType    string      `json:"event_type"`
	LatestOrigin string      `json:"latest_origin"`
	LatestPrice  float64     `json:"latest_price"`
	LatestStamp  int64       `json:"latest_stamp"`
	QuoteOrigin  string      `json:"quote_origin"`
	QuotePrice   float64     `json:"quote_price"`
	QuoteStamp   int64       `json:"quote_stamp"`
	IsExpired    bool        `json:"is_expired"`
	SrvNetwork   string      `json:"srv_network"`
	SrvPubkey    string      `json:"srv_pubkey"`
	TholdHash    string      `json:"thold_hash"`
	TholdKey     string      `json:"thold_key"`
	TholdPrice   float64     `json:"thold_price"`
	ReqID        string      `json:"req_id"`
	ReqSig       string      `json:"req_sig"`
}

// handleWebhook handles incoming webhook requests for ducat events.
// It accepts only POST requests and validates and processes the JSON webhook payload:
// - responds 405 if the method is not POST,
// - responds 400 for body read or JSON parsing errors,
// - uses an in-memory TTL cache (`processedEvents`) to ensure idempotent processing and returns 200 for duplicates,
// - parses the payload.Content into a PriceEvent and logs a structured message based on EventType ("create", "check_no_breach", "breach"),
// - logs a warning for unknown event types and always responds 200 OK for successfully received (or duplicate) events.
func handleWebhook(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("❌ Failed to read body: %v", err)
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}

	var payload WebhookPayload
	if err := json.Unmarshal(body, &payload); err != nil {
		log.Printf("❌ Failed to parse JSON: %v", err)
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Idempotency check using TTL cache - returns false if already processed
	if !processedEvents.Add(payload.EventID) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}

	// Parse the content to get PriceEvent details
	var priceEvent PriceEvent
	if err := json.Unmarshal([]byte(payload.Content), &priceEvent); err != nil {
		log.Printf("❌ Failed to parse event content for event_id=%s: %v", payload.EventID, err)
		http.Error(w, "Invalid event content", http.StatusBadRequest)
		return
	}

	// Handle different event types
	switch payload.EventType {
	case "create":
		log.Printf("✅ CREATE: %s | Threshold: $%.2f | Hash: %s",
			getTag(payload.Tags, "domain"),
			priceEvent.TholdPrice,
			priceEvent.TholdHash)

	case "check_no_breach":
		log.Printf("✅ CHECK: %s | Price: $%.2f still above threshold $%.2f",
			getTag(payload.Tags, "domain"),
			priceEvent.LatestPrice,
			priceEvent.TholdPrice)

	case "breach":
		log.Printf("🚨 BREACH: %s | Price: $%.2f breached threshold $%.2f | Secret: %s",
			getTag(payload.Tags, "domain"),
			priceEvent.LatestPrice,
			priceEvent.TholdPrice,
			priceEvent.TholdKey)

	default:
		log.Printf("⚠️  Unknown event type: %s", payload.EventType)
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// getTag retrieves the value associated with key from a slice of tag pairs.
// It returns the second element of the first tag whose first element equals key.
// If no matching tag is found or a tag has fewer than two elements, it returns an empty string.
func getTag(tags [][]string, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

// handleHealth writes an HTTP 200 response with the plain-text body "OK".
func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// main starts the HTTP server, registers the webhook and health handlers, logs startup
// information (including event cache configuration), and listens on port 8080.
// The function terminates the process if the server fails to start or stops with an error.
func main() {
	port := ":8080"

	http.HandleFunc("/webhook/ducat", handleWebhook)
	http.HandleFunc("/health", handleHealth)

	log.Println("🎯 DUCAT Webhook Server")
	log.Println(strings.Repeat("=", 80))
	log.Printf("🚀 Server starting on http://localhost%s", port)
	log.Printf("📍 Webhook endpoint: http://localhost%s/webhook/ducat", port)
	log.Printf("❤️  Health check: http://localhost%s/health", port)
	log.Printf("📊 Event cache: TTL=%v, MaxSize=%d, Cleanup=%v", EventTTL, MaxCacheSize, CleanupInterval)
	log.Println(strings.Repeat("=", 80))
	log.Println("Waiting for webhooks...\n")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("❌ Server failed: %v", err)
	}
}