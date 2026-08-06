package shared

const (
	// Threshold validation
	MinThresholdDistance = 0.01
	MaxQuoteAge          = 60
	MaxPriceValue        = 4294967295
	MaxDomainLength      = 253

	// Price bounds (BTC/USD)
	MinReasonablePrice = 1000.0
	MaxReasonablePrice = 1000000.0

	// Price adjustment bounds (H5).
	// The dev price-adjustment control can shift the published price by a
	// percentage. These cap how far it may move from the real Chainlink price so
	// a single (compromised or fat-fingered) control event cannot pin the oracle
	// arbitrarily far from market — which would let it drive unfair liquidations.
	// Enforced both when SETTING an adjustment (request validation) and when
	// APPLYING one (defense in depth, since the apply path must not trust the
	// control event's pct).
	MaxAdjustmentPct         = 50.0  // +50% ceiling
	MinAdjustmentPct         = -50.0 // -50% floor
	MaxAdjustmentDurationMin = 5     // 5 min max — a price override that drives liquidations must be short-lived

	// Price staleness (H5/H3). Max allowed skew (seconds) between the report's
	// signed observations timestamp and the server time. A report whose signed
	// timestamp is older than this is rejected (not just warned) — a stale or
	// replayed report must not drive liquidations.
	MaxPriceStalenessSec = 300 // 5 minutes

	// Batch limits. Evaluation performs one outbound relay read per unique hash,
	// in addition to price retries, adjustment lookup, breach publication, and an
	// optional callback. Fourteen keeps the worst case within CRE's 20-call cap.
	MaxBatchSize        = 14
	MaxParallelRequests = 14

	// Nostr event kinds (must match client-sdk query kinds)
	NostrEventKindThresholdCommitment = 30078 // Legacy, kept for adjustment control events
	NostrEventKindContract            = 30000 // Active price contracts
	NostrEventKindBreach              = 1000  // Breached price contracts (thold_key revealed)

	// Data sources
	OriginChainlinkDataStream = "chainlink_data_stream"

	// Event states
	EventTypeActive = "active"
	EventTypeBreach = "breach"

	// Hash lengths (hex-encoded)
	TholdHashLength     = 40
	CommitHashLength    = 64
	ContractIDLength    = 64
	TholdKeyLength      = 64
	OracleSigLength     = 128
	SchnorrPubkeyLength = 64
)
