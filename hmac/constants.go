//go:build wasip1

package main

const (
	// Threshold validation
	MinThresholdDistance = 0.01  // 1% min distance from current price
	MaxQuoteAge          = 86400 // 24 hours
	MaxPriceValue        = 1e12  // $1 trillion
	MaxDomainLength      = 253   // DNS spec limit

	// Price bounds (BTC/USD)
	MinReasonablePrice = 1000.0    // $1k
	MaxReasonablePrice = 1000000.0 // $1M

	// Nostr NIP-33 parameterized replaceable event
	NostrEventKindThresholdCommitment = 30078

	// Data sources
	OriginChainlinkDataStream = "chainlink_data_stream"

	// Event states
	EventTypeActive = "active"
	EventTypeBreach = "breach"

	// HMAC domain separators
	DomainSeparatorServer    = "DUCAT_SERVER_KEY_V1"
	DomainSeparatorThreshold = "DUCAT_THRESHOLD_V1"
)
