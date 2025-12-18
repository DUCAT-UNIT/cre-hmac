// Package shared contains types and validation logic shared between WASM and non-WASM code
package shared

const (
	// Threshold validation
	MinThresholdDistance = 0.01       // 1% min distance from current price
	MaxQuoteAge          = 86400      // 24 hours
	MaxPriceValue        = 4294967295 // uint32 max (~$4.3B) - must fit in 4-byte binary encoding
	MaxDomainLength      = 253        // DNS spec limit

	// Price bounds (BTC/USD)
	MinReasonablePrice = 1000.0    // $1k
	MaxReasonablePrice = 1000000.0 // $1M

	// Batch processing limits
	// MaxBatchSize limits the number of quotes that can be evaluated or generated in a single request.
	// This prevents excessive parallel HTTP requests to external services.
	// Note: The CRE SDK manages actual concurrency; this is a request-level limit.
	MaxBatchSize = 100

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
