//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// Request handlers for DUCAT threshold commitment system
//
// CREATE: New threshold quote with HMAC-derived secret
// EVALUATE: Batch check quotes, reveal secrets on breach
//
// Uses DON consensus for price data and relay operations

// createQuote creates new price threshold commitment
// 1. Fetch BTC/USD price with DON consensus
// 2. Validate threshold distance (1% min)
// 3. Derive threshold secret via HMAC
// 4. Compute Hash160 commitment
// createQuote creates a new threshold price commitment (quote) and publishes it as a Nostr event.
// It fetches the current price, validates the requested threshold is at least 1% away from the current price,
// constructs a PriceContractResponse (with the threshold secret withheld), signs a replaceable NIP-33 event,
// publishes the event to configured relays using consensus, and optionally sends a webhook callback.
// On success the published NostrEvent is returned; on failure an error is returned (for example: key derivation,
// price fetch, contract creation, event signing, or relay publish failures).
func createQuote(wc *WorkflowConfig, runtime cre.Runtime, requestData *HttpRequestData) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("Creating new quote", "domain", requestData.Domain, "tholdPrice", *requestData.TholdPrice)

	// Derive keys from private key bytes (from secrets)
	keys, err := deriveKeysFromBytes(wc.PrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero private key bytes after handler completes
	defer keys.Zero()

	// Fetch current BTC/USD price with consensus
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		logger.Error("Price fetch failed", "error", err)
		return nil, ErrPriceFetchFailed(err)
	}

	currentPrice, _ := priceData.Price.Float64()
	tholdPrice := *requestData.TholdPrice

	logger.Info("Fetched current price", "currentPrice", currentPrice, "tholdPrice", tholdPrice)

	// Validate threshold is not too close to current price
	// Two modes supported:
	// 1. Threshold > current: Immediate breach (testing/conditional release)
	// 2. Threshold < current: Delayed breach (downside protection)
	// For meaningful behavior, require at least 1% distance in either direction
	if tholdPrice > currentPrice {
		// Threshold above current (immediate breach mode)
		minThreshold := currentPrice * (1 + MinThresholdDistance)
		if tholdPrice < minThreshold {
			logger.Warn("Threshold too close to current price", "mode", "above", "minRequired", minThreshold, "got", tholdPrice)
			return nil, ErrThresholdTooClose()
		}
	} else {
		// Threshold below current (downside protection mode)
		maxThreshold := currentPrice * (1 - MinThresholdDistance)
		if tholdPrice > maxThreshold {
			logger.Warn("Threshold too close to current price", "mode", "below", "maxAllowed", maxThreshold, "got", tholdPrice)
			return nil, ErrThresholdTooClose()
		}
	}

	// Use price timestamp from data stream (DON consensus time via data)
	quoteStamp := priceData.Stamp

	// Create price contract using new core-ts aligned crypto
	// This computes: commit_hash, thold_key, thold_hash, contract_id, oracle_sig
	contract, err := createPriceContractFromBytes(
		wc.PrivateKeyBytes,
		keys.SchnorrPubkey,
		wc.Config.Network,
		uint32(currentPrice),
		uint32(quoteStamp),
		uint32(tholdPrice),
	)
	if err != nil {
		logger.Error("Price contract creation failed", "error", err)
		return nil, ErrContractCreationFailed(err)
	}

	// Build PriceContractResponse - matches core-ts PriceContract schema exactly
	// This is what gets stored in Nostr and what client-sdk expects to parse
	// Note: createPriceContract already computed oracle_sig, so we use it directly
	priceContract := PriceContractResponse{
		ChainNetwork: wc.Config.Network,      // Bitcoin network
		OraclePubkey: keys.SchnorrPubkey,     // Server Schnorr public key
		BasePrice:    int64(currentPrice),    // Quote price as int
		BaseStamp:    quoteStamp,             // Quote timestamp
		CommitHash:   contract.CommitHash,    // hash340 commitment
		ContractID:   contract.ContractID,    // Contract identifier
		OracleSig:    contract.OracleSig,     // Schnorr signature (from createPriceContract)
		TholdHash:    contract.TholdHash,     // Hash160 commitment
		TholdKey:     nil,                    // Secret is NOT revealed (null for active)
		TholdPrice:   int64(tholdPrice),      // Threshold price
	}

	// Marshal to JSON for Nostr event content
	eventJSON, err := json.Marshal(priceContract)
	if err != nil {
		return nil, fmt.Errorf("event marshaling failed: %w", err)
	}

	// Create Nostr event
	nostrEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", contract.CommitHash}, // NIP-33 replaceable event identifier
		},
		Content: string(eventJSON),
	}

	// Sign Nostr event
	if err := signNostrEvent(nostrEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("event signing failed: %w", err)
	}

	logger.Info("Created quote", "eventId", nostrEvent.ID, "tholdHash", contract.TholdHash)

	// Publish to relay with consensus
	relayRespPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishEvent(wc.Config, log, sr, nostrEvent)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := relayRespPromise.Await()
	if err != nil {
		logger.Error("Failed to publish to relay", "error", err)
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected event: %s", relayResp.Message)
	}

	logger.Info("Successfully published quote to relay", "eventId", nostrEvent.ID)

	// Send webhook callback if URL provided (single node execution after consensus)
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		// Capture priceContract for closure
		contract := &priceContract
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, nostrEvent, contract, "create")
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		// Await to ensure single execution, but ignore errors (best-effort)
		_, _ = webhookPromise.Await()
	}

	return nostrEvent, nil
}

// evaluateQuotes batch evaluates multiple quotes by their thold_hash IN PARALLEL
// Phase 1: Fetch price once, then launch ALL quote fetches in parallel
// Phase 2: Process results, prepare breach events (synchronous, fast)
// evaluateQuotes evaluates a batch of threshold quotes and publishes breach events when thresholds are crossed.
// 
// evaluateQuotes fetches the current reference price once, retrieves each quote event in parallel, determines
// whether each quote is active, already breached, or newly breached, and for newly breached quotes publishes
// corresponding breach events (revealing the threshold secret). It returns a summary of per-quote evaluation
// results, the current price used for evaluation, and the evaluation timestamp. If a callback URL is provided
// on the request, a best-effort JSON callback is sent after evaluation.
// 
// The function may return an error if key derivation or the initial price fetch fail.
func evaluateQuotes(wc *WorkflowConfig, runtime cre.Runtime, requestData *EvaluateQuotesRequest) (*EvaluateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Evaluating quotes batch (parallel)", "count", len(requestData.TholdHashes))

	// Derive keys from private key bytes (from secrets)
	keys, err := deriveKeysFromBytes(wc.PrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero private key bytes after handler completes
	defer keys.Zero()

	// Fetch current BTC/USD price with consensus (ONCE for all quotes)
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		logger.Error("Price fetch failed", "error", err)
		return nil, ErrPriceFetchFailed(err)
	}

	currentPrice, _ := priceData.Price.Float64()
	currentStamp := priceData.Stamp
	logger.Info("Fetched current price for batch evaluation", "currentPrice", currentPrice)

	// =========================================================================
	// PHASE 1: Launch ALL quote fetch requests in parallel
	// =========================================================================
	type FetchPromise struct {
		Index     int
		TholdHash string
		Promise   cre.Promise[*NostrEvent]
	}
	var fetchPromises []FetchPromise

	for i, tholdHash := range requestData.TholdHashes {
		// Capture for closure
		hash := tholdHash

		promise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*NostrEvent, error) {
				return fetchEventByDTag(wc.Config, log, sr, hash)
			},
			cre.ConsensusIdenticalAggregation[*NostrEvent](),
		)

		fetchPromises = append(fetchPromises, FetchPromise{
			Index:     i,
			TholdHash: tholdHash,
			Promise:   promise,
		})
	}

	logger.Info("Launched parallel fetch requests", "count", len(fetchPromises))

	// =========================================================================
	// PHASE 2: Await fetches, process results, prepare breach events
	// =========================================================================
	results := make([]QuoteEvaluationResult, len(requestData.TholdHashes))

	// Track breach events that need to be published
	type BreachToPublish struct {
		Index      int
		TholdHash  string
		Event      *NostrEvent
		TholdKey   string
	}
	var breachesToPublish []BreachToPublish

	for _, fp := range fetchPromises {
		result := QuoteEvaluationResult{
			TholdHash:    fp.TholdHash,
			CurrentPrice: currentPrice,
		}

		// Await fetch result
		originalEvent, err := fp.Promise.Await()
		if err != nil {
			errMsg := fmt.Sprintf("failed to fetch quote: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			logger.Warn("Failed to fetch quote", "tholdHash", fp.TholdHash, "error", err)
			continue
		}

		// Parse original event content as PriceContractResponse (core-ts PriceContract format)
		var originalData PriceContractResponse
		if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
			errMsg := fmt.Sprintf("failed to parse quote: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		result.TholdPrice = float64(originalData.TholdPrice)

		// SECURITY: Validate quote age before evaluating
		// Prevents replay attacks with stale price data
		// Uses configurable max age (M-2 fix)
		maxAge := wc.Config.GetMaxQuoteAge()
		if err := validateQuoteAge(int64(originalData.BaseStamp), currentStamp, maxAge); err != nil {
			errMsg := fmt.Sprintf("quote age validation failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			logger.Warn("Quote too old for evaluation", "tholdHash", fp.TholdHash, "baseStamp", originalData.BaseStamp, "error", err)
			continue
		}

		// Check if already breached (thold_key is revealed when breached)
		if originalData.TholdKey != nil {
			result.Status = "breached"
			result.TholdKey = originalData.TholdKey
			results[fp.Index] = result
			logger.Info("Quote already breached", "tholdHash", fp.TholdHash)
			continue
		}

		// Check breach condition (price fell below threshold)
		if currentPrice >= float64(originalData.TholdPrice) {
			result.Status = "active"
			result.TholdKey = nil
			results[fp.Index] = result
			logger.Info("Quote not breached", "tholdHash", fp.TholdHash, "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)
			continue
		}

		// BREACHED - prepare breach event for parallel publish
		logger.Info("Quote BREACHED - preparing event", "tholdHash", fp.TholdHash, "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

		// Regenerate commit hash to derive threshold key
		// Use PriceContract fields: oracle_pubkey, chain_network, base_price, base_stamp, thold_price
		commitHash, err := getPriceCommitHash(
			originalData.OraclePubkey,
			originalData.ChainNetwork,
			uint32(originalData.BasePrice),
			uint32(originalData.BaseStamp),
			uint32(originalData.TholdPrice),
		)
		if err != nil {
			errMsg := fmt.Sprintf("commit hash regeneration failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Regenerate threshold secret using private key bytes
		tholdSecret, err := getTholdKeyFromBytes(wc.PrivateKeyBytes, commitHash)
		if err != nil {
			errMsg := fmt.Sprintf("threshold key regeneration failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Verify secret matches original commitment
		if err := verifyThresholdCommitment(tholdSecret, originalData.TholdHash); err != nil {
			errMsg := fmt.Sprintf("commitment verification failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Compute contract ID for breach event
		contractID, err := getPriceContractID(commitHash, originalData.TholdHash)
		if err != nil {
			errMsg := fmt.Sprintf("contract ID computation failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Sign contract ID with Schnorr
		oracleSig, err := signSchnorr(keys.PrivateKey, contractID)
		if err != nil {
			errMsg := fmt.Sprintf("signing failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Build breach PriceContractResponse with REVEALED secret (core-ts PriceContract format)
		breachData := PriceContractResponse{
			ChainNetwork: originalData.ChainNetwork,
			OraclePubkey: originalData.OraclePubkey,
			BasePrice:    originalData.BasePrice,
			BaseStamp:    originalData.BaseStamp,
			CommitHash:   commitHash,
			ContractID:   contractID,
			OracleSig:    oracleSig,
			TholdHash:    originalData.TholdHash,
			TholdKey:     &tholdSecret, // SECRET REVEALED on breach
			TholdPrice:   originalData.TholdPrice,
		}

		breachJSON, err := json.Marshal(breachData)
		if err != nil {
			errMsg := fmt.Sprintf("marshal failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Create Nostr breach event (NIP-33 replaceable by d tag)
		breachEvent := &NostrEvent{
			PubKey:    keys.SchnorrPubkey,
			CreatedAt: currentStamp,
			Kind:      NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", commitHash}, // NIP-33 replaceable event identifier
			},
			Content: string(breachJSON),
		}

		if err := signNostrEvent(breachEvent, keys.PrivateKey); err != nil {
			errMsg := fmt.Sprintf("event signing failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[fp.Index] = result
			continue
		}

		// Queue for parallel publish
		breachesToPublish = append(breachesToPublish, BreachToPublish{
			Index:     fp.Index,
			TholdHash: fp.TholdHash,
			Event:     breachEvent,
			TholdKey:  tholdSecret,
		})

		// Set preliminary result (will update after publish)
		results[fp.Index] = result
	}

	logger.Info("Prepared breach events for parallel publish", "count", len(breachesToPublish))

	// =========================================================================
	// PHASE 3: Launch ALL breach event publishes in parallel
	// =========================================================================
	type PublishPromise struct {
		Breach  BreachToPublish
		Promise cre.Promise[*RelayResponse]
	}
	var publishPromises []PublishPromise

	for _, breach := range breachesToPublish {
		// Capture for closure
		event := breach.Event

		promise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				return publishEvent(wc.Config, log, sr, event)
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)

		publishPromises = append(publishPromises, PublishPromise{
			Breach:  breach,
			Promise: promise,
		})
	}

	logger.Info("Launched parallel publish requests", "count", len(publishPromises))

	// Await all publish results
	for _, pp := range publishPromises {
		relayResp, err := pp.Promise.Await()
		if err != nil || !relayResp.Success {
			errMsg := fmt.Sprintf("relay publish failed: %v", err)
			results[pp.Breach.Index].Error = &errMsg
			results[pp.Breach.Index].Status = "error"
			logger.Warn("Failed to publish breach event", "tholdHash", pp.Breach.TholdHash, "error", err)
			continue
		}

		// Update result with success
		results[pp.Breach.Index].Status = "breached"
		results[pp.Breach.Index].TholdKey = &pp.Breach.TholdKey
		logger.Info("Published breach event", "tholdHash", pp.Breach.TholdHash, "eventId", pp.Breach.Event.ID)
	}

	response := &EvaluateQuotesResponse{
		Results:      results,
		CurrentPrice: currentPrice,
		EvaluatedAt:  currentStamp,
	}

	// Compute summary with aggregated error information
	response.ComputeSummary()

	logger.Info("Batch evaluation complete (parallel)",
		"total", response.Summary.Total,
		"breached", response.Summary.Breached,
		"active", response.Summary.Active,
		"errors", response.Summary.Errors,
		"currentPrice", currentPrice)

	// Send webhook callback if URL provided
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		trackingDomain := "eval-batch"
		if len(requestData.TholdHashes) > 0 {
			trackingDomain = fmt.Sprintf("eval-%s", requestData.TholdHashes[0][:8])
		}
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendJSONCallback(wc.Config, log, sr, *requestData.CallbackURL, trackingDomain, "evaluate", response)
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		_, _ = webhookPromise.Await()
	}

	return response, nil
}

// QuoteJob represents a single quote to be generated
type QuoteJob struct {
	Rate       float64
	TholdPrice float64
	Domain     string
}

// QuoteResult represents the result of generating a single quote
type QuoteResult struct {
	Rate      float64
	TholdHash string
	Success   bool
	Error     error
}

// generateQuotesParallel auto-generates price quotes in parallel
// generateQuotesParallel generates threshold quotes across the specified rate range, publishes each as a Nostr threshold-commitment event in parallel, and returns a summary of the successfully created quotes.
//
// RATE LIMITING: Before generating, checks the relay for the most recent quote timestamp.
// If a quote was generated within MinCronIntervalSeconds, skips generation to prevent
// excessive relay writes and potential DoS from misconfigured cron schedules.
//
// The function obtains the current reference price, creates and signs price contracts for each rate step, publishes the signed Nostr events concurrently, and aggregates the created threshold hashes and counts. If a gateway callback URL is configured, a best-effort batch callback is sent after publishing.
//
// It returns a GenerateQuotesResponse containing counts, generated thold hashes, the base price and timestamp, and an error if a fatal step (such as price fetch or key derivation) fails.
func generateQuotesParallel(wc *WorkflowConfig, runtime cre.Runtime, requestData *GenerateQuotesRequest) (*GenerateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Generating quotes (parallel)", "rateMin", requestData.RateMin, "rateMax", requestData.RateMax, "stepSize", requestData.StepSize)

	// Derive keys from private key bytes
	keys, err := deriveKeysFromBytes(wc.PrivateKeyBytes)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	// SECURITY: Zero private key bytes after handler completes
	defer keys.Zero()

	// RATE LIMITING: Check if we've generated quotes recently
	// This prevents excessive relay writes if cron fires too frequently
	client := &http.Client{}
	minInterval := wc.Config.GetMinCronInterval()
	if minInterval > 0 {
		latestPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (int64, error) {
				return fetchLatestQuoteTimestamp(wc.Config, log, sr, keys.SchnorrPubkey)
			},
			cre.ConsensusAggregationFromTags[int64](),
		)
		latestTimestamp, err := latestPromise.Await()
		if err != nil {
			logger.Warn("Failed to check rate limit (proceeding with generation)", "error", err)
		} else if latestTimestamp > 0 {
			// Check if enough time has passed since last generation
			currentTime := runtime.Time().Unix()
			elapsed := currentTime - latestTimestamp
			if elapsed < minInterval {
				logger.Info("Rate limit: skipping generation, last batch too recent",
					"lastBatchAge", elapsed,
					"minInterval", minInterval,
					"secondsUntilAllowed", minInterval-elapsed,
				)
				return &GenerateQuotesResponse{
					QuotesCreated: 0,
					CurrentPrice:  0,
					TholdHashes:   []string{},
					GeneratedAt:   runtime.Time().Unix(),
					Skipped:       true,
					SkipReason:    fmt.Sprintf("rate limited: last batch %ds ago, min interval %ds", elapsed, minInterval),
				}, nil
			}
			logger.Info("Rate limit check passed", "lastBatchAge", elapsed, "minInterval", minInterval)
		}
	}

	// Fetch current BTC/USD price with consensus
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		logger.Error("Price fetch failed", "error", err)
		return nil, ErrPriceFetchFailed(err)
	}

	currentPrice, _ := priceData.Price.Float64()
	quoteStamp := priceData.Stamp
	logger.Info("Fetched current price for parallel quote generation", "currentPrice", currentPrice)

	// Use QuoteDomain if provided, otherwise use Domain
	quoteDomainPrefix := requestData.QuoteDomain
	if quoteDomainPrefix == "" {
		quoteDomainPrefix = requestData.Domain
	}

	// Build list of quotes to generate
	var jobs []QuoteJob
	var minThold, maxThold float64

	// SECURITY: Validate current price doesn't exceed uint32 max
	if currentPrice > float64(MaxPriceValue) {
		logger.Error("Current price exceeds maximum", "price", currentPrice, "max", MaxPriceValue)
		return nil, ErrPriceInvalid(fmt.Errorf("price exceeds maximum"))
	}

	for rate := requestData.RateMin; rate <= requestData.RateMax+0.0001; rate += requestData.StepSize {
		tholdPrice := currentPrice * rate

		// SECURITY: Skip threshold prices that would overflow uint32
		if tholdPrice > float64(MaxPriceValue) {
			logger.Warn("Skipping threshold price exceeding uint32 max", "rate", rate, "tholdPrice", tholdPrice)
			continue
		}

		// Track min/max thresholds
		if minThold == 0 || tholdPrice < minThold {
			minThold = tholdPrice
		}
		if tholdPrice > maxThold {
			maxThold = tholdPrice
		}

		jobs = append(jobs, QuoteJob{
			Rate:       rate,
			TholdPrice: tholdPrice,
			Domain:     fmt.Sprintf("%s-%.2f", quoteDomainPrefix, rate),
		})
	}

	logger.Info("Prepared quote generation jobs", "count", len(jobs))

	// Create all signed events first (synchronous, fast)
	type SignedEvent struct {
		Job       QuoteJob
		Event     *NostrEvent
		TholdHash string
	}
	var signedEvents []SignedEvent

	for _, job := range jobs {
		// Create price contract - this already signs the contract (OracleSig is populated)
		contract, err := createPriceContractFromBytes(
			wc.PrivateKeyBytes,
			keys.SchnorrPubkey,
			wc.Config.Network,
			uint32(currentPrice),
			uint32(quoteStamp),
			uint32(job.TholdPrice),
		)
		if err != nil {
			logger.Warn("Failed to create contract", "rate", job.Rate, "error", err)
			continue
		}

		// Build PriceContractResponse - matches core-ts PriceContract schema exactly
		// NOTE: Use contract.OracleSig from createPriceContractFromBytes - no need to sign again
		eventData := PriceContractResponse{
			ChainNetwork: wc.Config.Network,
			OraclePubkey: keys.SchnorrPubkey,
			BasePrice:    int64(currentPrice),
			BaseStamp:    quoteStamp,
			CommitHash:   contract.CommitHash,
			ContractID:   contract.ContractID,
			OracleSig:    contract.OracleSig, // Use signature from contract creation (M-1 fix)
			TholdHash:    contract.TholdHash,
			TholdKey:     nil, // Secret NOT revealed for active quotes
			TholdPrice:   int64(job.TholdPrice),
		}

		eventJSON, err := json.Marshal(eventData)
		if err != nil {
			logger.Warn("Failed to marshal event", "rate", job.Rate, "error", err)
			continue
		}

		// Create Nostr event
		nostrEvent := &NostrEvent{
			PubKey:    keys.SchnorrPubkey,
			CreatedAt: quoteStamp,
			Kind:      NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", contract.CommitHash}, // NIP-33 replaceable event identifier
			},
			Content: string(eventJSON),
		}

		if err := signNostrEvent(nostrEvent, keys.PrivateKey); err != nil {
			logger.Warn("Failed to sign event", "rate", job.Rate, "error", err)
			continue
		}

		signedEvents = append(signedEvents, SignedEvent{
			Job:       job,
			Event:     nostrEvent,
			TholdHash: contract.TholdHash,
		})
	}

	logger.Info("Signed events prepared", "count", len(signedEvents))

	// Collect all events for batch publish
	var events []*NostrEvent
	var tholdHashes []string
	for _, se := range signedEvents {
		events = append(events, se.Event)
		tholdHashes = append(tholdHashes, se.TholdHash)
	}

	// Publish all events in a single batch request with retry
	// Retry up to 3 times with exponential backoff on failure
	const maxRetries = 3
	var quotesCreated int
	var lastErr error

	for attempt := 1; attempt <= maxRetries; attempt++ {
		batchPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				return publishEventsBatch(wc.Config, log, sr, events)
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)

		relayResp, err := batchPromise.Await()
		if err != nil {
			lastErr = err
			logger.Warn("Batch publish attempt failed", "attempt", attempt, "maxRetries", maxRetries, "error", err)
			continue
		}

		if !relayResp.Success {
			lastErr = fmt.Errorf("relay rejected batch: %s", relayResp.Message)
			logger.Warn("Batch publish attempt rejected", "attempt", attempt, "maxRetries", maxRetries, "message", relayResp.Message)
			continue
		}

		// Success
		quotesCreated = len(signedEvents)
		lastErr = nil
		logger.Info("Batch publish successful", "attempt", attempt, "count", quotesCreated)
		break
	}

	// Clear results on complete failure
	if lastErr != nil {
		logger.Error("Batch publish failed after all retries", "error", lastErr, "attempts", maxRetries)
		tholdHashes = nil
		quotesCreated = 0
	}

	logger.Info("Quote generation complete", "created", quotesCreated, "total", len(jobs))

	response := &GenerateQuotesResponse{
		QuotesCreated: quotesCreated,
		CurrentPrice:  currentPrice,
		TholdHashes:   tholdHashes,
		GeneratedAt:   quoteStamp,
	}
	response.Range.MinThold = minThold
	response.Range.MaxThold = maxThold

	// Send callback to gateway with base price (if configured)
	if wc.Config.GatewayCallbackURL != "" {
		batchInfo := &BatchGeneratedInfo{
			BasePrice: int64(currentPrice),
			BaseStamp: quoteStamp,
		}
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendBatchGeneratedCallback(wc.Config, log, sr, wc.Config.GatewayCallbackURL, batchInfo)
				return &RelayResponse{Success: true, Message: "callback sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		_, _ = webhookPromise.Await()
	}

	return response, nil
}

// sendWebhookCallback sends HTTP POST notification to callback URL
// Notifies external systems of workflow completion with results
// This is a best-effort notification - failures are logged but don't block the workflow
// sendWebhookCallback sends a JSON webhook POST containing the price contract and related metadata to the provided callback URL.
// It performs best-effort delivery: errors and non-2xx responses are logged but not returned to the caller.
// The payload includes `event_type`, `event_id`, `domain` (extracted from the event tags), `thold_hash`, and `price_contract`.
func sendWebhookCallback(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, event *NostrEvent, priceContract *PriceContractResponse, eventType string) {
	logger.Info("Sending webhook callback", "url", callbackURL, "eventType", eventType)

	// Prepare callback payload with price_contract at top level
	callbackPayload := map[string]interface{}{
		"event_type":     eventType,
		"event_id":       event.ID,
		"domain":         getDomainFromTags(event.Tags),
		"thold_hash":     priceContract.TholdHash,
		"price_contract": priceContract,
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal callback payload", "error", err)
		return
	}

	// Send POST request to callback URL (no consensus required for notifications)
	resp, err := sendRequester.SendRequest(&http.Request{
		Url:    callbackURL,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: callbackJSON,
	}).Await()

	if err != nil {
		logger.Error("Webhook callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("Webhook callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("Webhook callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode, "body", string(resp.Body))
	}
}

// getDomainFromTags extracts identifier from Nostr event tags
// Looks for "d" tag (NIP-33 replaceable event identifier) which contains commit_hash
// getDomainFromTags extracts the domain identifier from a Nostr event's tags.
// It returns the value of the first tag whose key is "d" or "domain", or an empty string if no such tag is present.
func getDomainFromTags(tags [][]string) string {
	for _, tag := range tags {
		if len(tag) >= 2 && (tag[0] == "d" || tag[0] == "domain") {
			return tag[1]
		}
	}
	return ""
}

// sendJSONCallback sends HTTP POST notification with JSON payload
// sendJSONCallback sends a best-effort JSON POST to the provided callbackURL containing an event wrapper
// with keys "event_type", "event_id" (formatted as "<eventType>-0"), "domain", and "data".
//
// The function marshals the wrapper to JSON, POSTs it with Content-Type "application/json" using
// sendRequester, and logs failures or non-2xx responses. Errors are handled locally and not returned.
func sendJSONCallback(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, domain string, eventType string, data interface{}) {
	logger.Info("Sending JSON callback", "url", callbackURL, "eventType", eventType, "domain", domain)

	// Prepare callback payload - clean format matching gateway's WebhookPayload
	callbackPayload := map[string]interface{}{
		"event_type": eventType,
		"event_id":   fmt.Sprintf("%s-%d", eventType, 0),
		"domain":     domain,
		"data":       data, // Direct data - no JSON string encoding
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal callback payload", "error", err)
		return
	}

	// Send POST request to callback URL
	resp, err := sendRequester.SendRequest(&http.Request{
		Url:    callbackURL,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: callbackJSON,
	}).Await()

	if err != nil {
		logger.Error("JSON callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("JSON callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("JSON callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode, "body", string(resp.Body))
	}
}

// sendBatchGeneratedCallback notifies gateway that a new batch of quotes was generated
// sendBatchGeneratedCallback sends a best-effort HTTP POST notifying a gateway that a new batch of quotes was generated.
// The JSON payload has an `event_type` of "batch_generated" and a `data` field containing the provided BatchGeneratedInfo.
// It logs success for 2xx responses and logs errors or non-2xx responses; failures are not propagated.
func sendBatchGeneratedCallback(config *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, batchInfo *BatchGeneratedInfo) {
	logger.Info("Sending batch generated callback", "url", callbackURL, "basePrice", batchInfo.BasePrice, "baseStamp", batchInfo.BaseStamp)

	callbackPayload := map[string]interface{}{
		"event_type": "batch_generated",
		"data":       batchInfo,
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal batch callback payload", "error", err)
		return
	}

	resp, err := sendRequester.SendRequest(&http.Request{
		Url:    callbackURL,
		Method: "POST",
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: callbackJSON,
	}).Await()

	if err != nil {
		logger.Error("Batch generated callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("Batch generated callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("Batch generated callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode)
	}
}