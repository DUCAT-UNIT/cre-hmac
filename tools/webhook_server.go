package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
)

// Idempotency tracking - stores processed event IDs
var (
	processedEvents = make(map[string]bool)
	eventsMutex     sync.RWMutex
)

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

	// Idempotency check - only process each event_id once
	eventsMutex.Lock()
	if processedEvents[payload.EventID] {
		eventsMutex.Unlock()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
		return
	}
	processedEvents[payload.EventID] = true
	eventsMutex.Unlock()

	// Parse the content to get PriceEvent details
	var priceEvent PriceEvent
	json.Unmarshal([]byte(payload.Content), &priceEvent)

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

func getTag(tags [][]string, key string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && tag[0] == key {
			return tag[1]
		}
	}
	return ""
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func main() {
	port := ":8080"

	http.HandleFunc("/webhook/ducat", handleWebhook)
	http.HandleFunc("/health", handleHealth)

	log.Println("🎯 DUCAT Webhook Server")
	log.Println(strings.Repeat("=", 80))
	log.Printf("🚀 Server starting on http://localhost%s", port)
	log.Printf("📍 Webhook endpoint: http://localhost%s/webhook/ducat", port)
	log.Printf("❤️  Health check: http://localhost%s/health", port)
	log.Println(strings.Repeat("=", 80))
	log.Println("Waiting for webhooks...\n")

	if err := http.ListenAndServe(port, nil); err != nil {
		log.Fatalf("❌ Server failed: %v", err)
	}
}
