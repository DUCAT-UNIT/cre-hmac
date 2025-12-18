// Package shared contains types and validation logic shared between WASM and non-WASM code
package shared

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

	// Hash lengths
	TholdHashLength    = 40  // 20 bytes hex-encoded
	CommitHashLength   = 64  // 32 bytes hex-encoded
	ContractIDLength   = 64  // 32 bytes hex-encoded
	TholdKeyLength     = 64  // 32 bytes hex-encoded
	OracleSigLength    = 128 // 64 bytes hex-encoded
	SchnorrPubkeyLength = 64 // 32 bytes hex-encoded
)
