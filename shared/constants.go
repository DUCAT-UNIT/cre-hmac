// Package shared contains types and validation logic shared between WASM and non-WASM code
package shared

const (
	// Threshold validation
	MinThresholdDistance = 0.01       // 1% min distance from current price
	MaxQuoteAge          = 60         // 60 seconds - BTC can move 5%+ in minutes, keep quotes fresh
	MaxPriceValue        = 4294967295 // uint32 max (~$4.3B) - must fit in 4-byte binary encoding
	MaxDomainLength      = 253        // DNS spec limit

	// Price bounds (BTC/USD)
	MinReasonablePrice = 1000.0    // $1k
	MaxReasonablePrice = 1000000.0 // $1M

	// Batch processing limits
	// MaxBatchSize limits the number of quotes that can be evaluated or generated in a single request.
	// CRE has a 30KB max request size. Each thold_hash is ~45 bytes, so max ~650 per request.
	// Using 500 for safety margin with JSON-RPC wrapper overhead.
	MaxBatchSize = 500

	// MaxParallelRequests is the recommended limit for concurrent HTTP requests within a single
	// workflow execution. The CRE runtime may enforce its own limits, but handlers should
	// respect this as a best practice to avoid overwhelming external services.
	MaxParallelRequests = 50

	// Nostr NIP-33 parameterized replaceable event
	NostrEventKindThresholdCommitment = 30078

	// Data sources
	OriginChainlinkDataStream = "chainlink_data_stream"

	// Event states
	EventTypeActive = "active"
	EventTypeBreach = "breach"

	// Hash lengths
	TholdHashLength     = 40  // 20 bytes hex-encoded
	CommitHashLength    = 64  // 32 bytes hex-encoded
	ContractIDLength    = 64  // 32 bytes hex-encoded
	TholdKeyLength      = 64  // 32 bytes hex-encoded
	OracleSigLength     = 128 // 64 bytes hex-encoded
	SchnorrPubkeyLength = 64  // 32 bytes hex-encoded
)
