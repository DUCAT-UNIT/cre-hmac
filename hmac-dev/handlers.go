//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// Unified cron HTTP-call budget. Historically this tracked the deployed CRE
// consensus-call cap of 20. Under TEE execution requests go out via
// SendRequestInTee (no consensus rounds), but the budget is kept as a
// conservative self-imposed guard until the confidential-execution capability
// limits are published. The teeSender counts every actual outbound request —
// including fetchPrice's internal retries — so the guard meters real enclave
// HTTP calls, not loop rounds.
//
//	1  — Chainlink price fetch (up to 3 per round on transient failures)
//	1  — adjustment-control read
//	1  — kind-10001 pending snapshot publish
//	7  — full 1.36–10.00 ladder = 7 chunks of 130 events
//	1  — kind-10000 current snapshot publish
//	-----
//	11 used on the happy path; 9 calls of retry headroom remain.
const (
	unifiedTotalCallBudget = 20
	unifiedRetryWaitSec    = 5

	// Per-phase retry caps. Sum kept under unifiedTotalCallBudget with room
	// for chunk-level retries.
	unifiedPriceMaxAttempts       = 3
	unifiedSnapshotPubMaxAttempts = 3
	unifiedCurrentPubMaxAttempts  = 3
)

func isNonRetryablePriceFetchError(err error) bool {
	if err == nil {
		return false
	}

	msg := err.Error()
	return strings.Contains(msg, "feeds not authorized") ||
		strings.Contains(msg, "price request failed with status 401") ||
		strings.Contains(msg, "price request failed with status 403") ||
		(strings.Contains(msg, "price request failed with status 404") &&
			strings.Contains(msg, "report not found"))
}

// createQuote creates a new threshold commitment and publishes it as a Nostr event.
// In the dev workflow, it checks for an active price adjustment before using the price.
func createQuote(wc *WorkflowConfig, runtime cre.TeeRuntime, requestData *HttpRequestData) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("Creating new quote (dev)", "domain", requestData.Domain, "tholdPrice", *requestData.TholdPrice)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current BTC/USD price from inside the enclave
	sender := newTeeSender(runtime)
	priceData, err := fetchPrice(wc, logger, sender)
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	quoteStamp := priceData.Stamp

	// Check for active price adjustment
	currentPrice, adjusted := applyActiveAdjustment(wc, sender, currentPrice, quoteStamp, keys.SchnorrPubkey, logger)
	if adjusted {
		if err := validatePriceForEncoding(currentPrice); err != nil {
			return nil, fmt.Errorf("adjusted price out of bounds: %w", err)
		}
	}

	tholdPrice := *requestData.TholdPrice

	logger.Info("Using price for quote", "price", currentPrice, "adjusted", adjusted, "tholdPrice", tholdPrice)

	// Validate threshold distance
	if tholdPrice > currentPrice {
		minThreshold := currentPrice * (1 + MinThresholdDistance)
		if tholdPrice < minThreshold {
			return nil, fmt.Errorf("threshold too close to current price (above): min %.2f, got %.2f", minThreshold, tholdPrice)
		}
	} else {
		maxThreshold := currentPrice * (1 - MinThresholdDistance)
		if tholdPrice > maxThreshold {
			return nil, fmt.Errorf("threshold too close to current price (below): max %.2f, got %.2f", maxThreshold, tholdPrice)
		}
	}

	contract, err := createPriceContract(
		wc.PrivateKey,
		keys.SchnorrPubkey,
		wc.Config.Network,
		uint32(currentPrice),
		uint32(quoteStamp),
		uint32(math.Ceil(tholdPrice)),
	)
	if err != nil {
		return nil, fmt.Errorf("price contract creation failed: %w", err)
	}

	priceContract := PriceContractResponse{
		ChainNetwork: wc.Config.Network,
		OraclePubkey: keys.SchnorrPubkey,
		BasePrice:    int64(currentPrice),
		BaseStamp:    quoteStamp,
		CommitHash:   contract.CommitHash,
		ContractID:   contract.ContractID,
		OracleSig:    contract.OracleSig,
		TholdHash:    contract.TholdHash,
		TholdKey:     nil,
		TholdPrice:   int64(math.Ceil(tholdPrice)),
	}

	eventJSON, err := json.Marshal(priceContract)
	if err != nil {
		return nil, fmt.Errorf("event marshaling failed: %w", err)
	}

	nostrEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      NostrEventKindContract,
		Tags: [][]string{
			{"d", contract.CommitHash},
			{"h", contract.TholdHash},
			{"domain", requestData.Domain},
		},
		Content: string(eventJSON),
	}

	if err := signNostrEvent(nostrEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("event signing failed: %w", err)
	}

	logger.Info("Created quote (v2)", "eventId", nostrEvent.ID, "tholdHash", contract.TholdHash)

	// Publish to relay
	relayResp, err := publishEvent(wc.Config, logger, sender, nostrEvent)
	if err != nil {
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected event: %s", relayResp.Message)
	}

	// Send webhook callback if URL provided
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		sendWebhookCallback(wc.Config, logger, sender, *requestData.CallbackURL, nostrEvent, &priceContract, "create")
	}

	return nostrEvent, nil
}

// fetchQuote looks up an existing quote on the relay by thold_hash and returns it.
func fetchQuote(wc *WorkflowConfig, runtime cre.TeeRuntime, requestData *HttpRequestData) (*PriceEvent, error) {
	logger := runtime.Logger()
	tholdHash := *requestData.TholdHash
	logger.Info("Fetching existing quote", "domain", requestData.Domain, "tholdHash", tholdHash)

	// SECURITY (M7): derive the oracle pubkey so the relay read can pin the
	// quote author to this oracle's own key.
	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()
	oraclePubkey := keys.SchnorrPubkey

	sender := newTeeSender(runtime)
	fetchResult, err := fetchEventByDTag(wc.Config, logger, sender, tholdHash, oraclePubkey)
	if err != nil {
		return nil, fmt.Errorf("relay fetch failed: %w", err)
	}
	if fetchResult.Error != nil {
		return nil, fmt.Errorf("relay fetch error: %s", *fetchResult.Error)
	}
	if fetchResult.Event.ID == "" {
		return nil, fmt.Errorf("quote not found for thold_hash %s", tholdHash)
	}

	var contract PriceContractResponse
	if err := json.Unmarshal([]byte(fetchResult.Event.Content), &contract); err != nil {
		return nil, fmt.Errorf("failed to parse quote content: %w", err)
	}

	priceEvent := contract.ToPriceEvent(wc.Config.Network)
	logger.Info("Fetched existing quote", "tholdHash", tholdHash, "basePrice", contract.BasePrice, "tholdPrice", contract.TholdPrice)

	// Send webhook callback if URL provided
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		sendWebhookCallback(wc.Config, logger, sender, *requestData.CallbackURL, &fetchResult.Event, &contract, "fetch")
	}

	return priceEvent, nil
}

// evaluateQuotes batch evaluates quotes, revealing secrets for any that are breached.
// In the dev workflow, it checks for an active price adjustment before evaluating.
func evaluateQuotes(wc *WorkflowConfig, runtime cre.TeeRuntime, requestData *EvaluateQuotesRequest) (*EvaluateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Evaluating quotes batch (dev)", "count", len(requestData.TholdHashes))

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current BTC/USD price
	sender := newTeeSender(runtime)
	priceData, err := fetchPrice(wc, logger, sender)
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	currentStamp := priceData.Stamp

	// Check for active price adjustment
	currentPrice, adjusted := applyActiveAdjustment(wc, sender, currentPrice, currentStamp, keys.SchnorrPubkey, logger)
	// SECURITY (M9): re-validate the adjusted price before it drives breach
	// decisions, matching createQuote/generateQuotes.
	if adjusted {
		if err := validatePriceForEncoding(currentPrice); err != nil {
			return nil, fmt.Errorf("adjusted price out of bounds: %w", err)
		}
	}

	logger.Info("Using price for evaluation", "currentPrice", currentPrice, "adjusted", adjusted)

	// PHASE 1: Fetch quotes one-by-one (kept from the consensus-era design so
	// per-quote errors stay isolated; each fetch is one enclave HTTP call).
	fetchResultMap := make(map[string]*BatchFetchResult, len(requestData.TholdHashes))
	for _, dTag := range requestData.TholdHashes {
		fetchResp, fetchErr := fetchEventByDTag(wc.Config, logger, sender, dTag, keys.SchnorrPubkey)
		if fetchErr != nil {
			errMsg := fmt.Sprintf("failed to fetch quote: %v", fetchErr)
			fetchResultMap[dTag] = &BatchFetchResult{DTag: dTag, Error: &errMsg}
			continue
		}
		if fetchResp == nil {
			errMsg := "empty fetch response"
			fetchResultMap[dTag] = &BatchFetchResult{DTag: dTag, Error: &errMsg}
			continue
		}
		fetchResultMap[dTag] = fetchResp
	}

	// PHASE 2: Process results
	results := make([]QuoteEvaluationResult, len(requestData.TholdHashes))

	type BreachToPublish struct {
		Index     int
		TholdHash string
		Event     *NostrEvent
		TholdKey  string
	}
	var breachesToPublish []BreachToPublish

	for i, tholdHash := range requestData.TholdHashes {
		result := QuoteEvaluationResult{
			TholdHash:    tholdHash,
			CurrentPrice: currentPrice,
		}

		fetchResult, exists := fetchResultMap[tholdHash]
		if !exists || fetchResult.Error != nil {
			errMsg := "failed to fetch quote"
			if fetchResult != nil && fetchResult.Error != nil {
				errMsg = *fetchResult.Error
			}
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		originalEvent := fetchResult.Event
		if originalEvent.ID == "" {
			errMsg := "event not found"
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		var originalData PriceContractResponse
		if err := json.Unmarshal([]byte(originalEvent.Content), &originalData); err != nil {
			errMsg := fmt.Sprintf("failed to parse quote: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		result.TholdPrice = float64(originalData.TholdPrice)

		if int64(originalData.BaseStamp) > currentStamp+5 {
			errMsg := fmt.Sprintf("quote timestamp is in the future: base_stamp=%d current=%d", originalData.BaseStamp, currentStamp)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		if originalData.TholdKey != nil {
			result.Status = "breached"
			result.TholdKey = originalData.TholdKey
			results[i] = result
			continue
		}

		// Check breach condition (price fell below threshold)
		if currentPrice >= float64(originalData.TholdPrice) {
			result.Status = "active"
			result.TholdKey = nil
			results[i] = result
			continue
		}

		// BREACHED
		logger.Info("Quote BREACHED", "tholdHash", tholdHash, "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice)

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
			results[i] = result
			continue
		}

		tholdSecret, err := getTholdKey(wc.PrivateKey, commitHash)
		if err != nil {
			errMsg := fmt.Sprintf("threshold key regeneration failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		if err := verifyThresholdCommitment(tholdSecret, originalData.TholdHash); err != nil {
			errMsg := fmt.Sprintf("commitment verification failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		contractID, err := getPriceContractID(commitHash, originalData.TholdHash)
		if err != nil {
			errMsg := fmt.Sprintf("contract ID computation failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		oracleSig, err := signSchnorr(keys.PrivateKey, contractID)
		if err != nil {
			errMsg := fmt.Sprintf("signing failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		breachData := PriceContractResponse{
			ChainNetwork: originalData.ChainNetwork,
			OraclePubkey: originalData.OraclePubkey,
			BasePrice:    originalData.BasePrice,
			BaseStamp:    originalData.BaseStamp,
			CommitHash:   commitHash,
			ContractID:   contractID,
			OracleSig:    oracleSig,
			TholdHash:    originalData.TholdHash,
			TholdKey:     &tholdSecret,
			TholdPrice:   originalData.TholdPrice,
		}

		breachJSON, err := json.Marshal(breachData)
		if err != nil {
			errMsg := fmt.Sprintf("marshal failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		breachEvent := &NostrEvent{
			PubKey:    keys.SchnorrPubkey,
			CreatedAt: currentStamp,
			Kind:      NostrEventKindBreach,
			Tags: [][]string{
				{"d", commitHash},
				{"h", contractID},
				{"h", commitHash},
				{"h", originalData.TholdHash},
			},
			Content: string(breachJSON),
		}

		if err := signNostrEvent(breachEvent, keys.PrivateKey); err != nil {
			errMsg := fmt.Sprintf("event signing failed: %v", err)
			result.Error = &errMsg
			result.Status = "error"
			results[i] = result
			continue
		}

		breachesToPublish = append(breachesToPublish, BreachToPublish{
			Index:     i,
			TholdHash: tholdHash,
			Event:     breachEvent,
			TholdKey:  tholdSecret,
		})

		results[i] = result
	}

	// PHASE 3: Batch publish breach events
	if len(breachesToPublish) > 0 {
		var breachEvents []*NostrEvent
		for _, breach := range breachesToPublish {
			breachEvents = append(breachEvents, breach.Event)
		}

		batchPublishResp, err := publishEventsBatch(wc.Config, logger, sender, breachEvents)
		if err != nil {
			errMsg := fmt.Sprintf("batch publish failed: %v", err)
			for _, breach := range breachesToPublish {
				results[breach.Index].Error = &errMsg
				results[breach.Index].Status = "error"
			}
		} else if !batchPublishResp.Success {
			errMsg := fmt.Sprintf("batch publish rejected: %s", batchPublishResp.Message)
			for _, breach := range breachesToPublish {
				results[breach.Index].Error = &errMsg
				results[breach.Index].Status = "error"
			}
		} else {
			for _, breach := range breachesToPublish {
				results[breach.Index].Status = "breached"
				results[breach.Index].TholdKey = &breach.TholdKey
			}
		}
	}

	response := &EvaluateQuotesResponse{
		Results:      results,
		CurrentPrice: currentPrice,
		EvaluatedAt:  currentStamp,
	}
	response.ComputeSummary()

	// Send webhook callback if URL provided
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		trackingDomain := "eval-batch"
		if len(requestData.TholdHashes) > 0 {
			trackingDomain = fmt.Sprintf("eval-%s", requestData.TholdHashes[0][:8])
		}
		sendJSONCallback(wc.Config, logger, sender, *requestData.CallbackURL, trackingDomain, "evaluate", response)
	}

	return response, nil
}

// QuoteJob represents a single quote to be generated.
type QuoteJob struct {
	Rate       float64
	TholdPrice float64
	Domain     string
}

// runUnifiedCycle is the single dev cron handler. In one CRE execution it:
//
//  1. fetches BTC/USD from Chainlink Data Streams (with retries)
//  2. checks the price-adjustment control event and applies any active pct
//  3. publishes the kind-10001 pending snapshot
//  4. generates the full kind-30000 ladder for the configured rate range and
//     publishes it in MaxEventsPerBatch-sized chunks
//  5. publishes the kind-10000 current snapshot — only if all ladder chunks
//     succeeded, so wallets never see a kind-10000 whose ladder isn't on the
//     relay
//
// Because promotion is now in-process, the completion-marker scheme is gone:
// step (5) is guarded by in-memory success of step (4). A failure in any step
// returns an error and skips later steps — next cron tick re-runs the whole
// cycle. NIP-33 replacement makes everything idempotent.
//
// HTTP-call accounting (CRE budget: 20):
//
//	1  price fetch        (+ up to unifiedPriceMaxAttempts retries)
//	1  adjustment read
//	1  kind-10001 publish (+ up to unifiedSnapshotPubMaxAttempts retries)
//	7  ladder chunks      (full 1.36–10.00 range = 865 events / 130 per chunk)
//	1  kind-10000 publish (+ up to unifiedCurrentPubMaxAttempts retries)
//	-----
//	11 happy-path; 9 retry slots remain.
func runUnifiedCycle(wc *WorkflowConfig, runtime cre.TeeRuntime, requestData *GenerateQuotesRequest) (*GenerateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Unified dev cycle started",
		"rateMin", requestData.RateMin,
		"rateMax", requestData.RateMax,
		"stepSize", requestData.StepSize,
	)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// The teeSender counts every real outbound request (including fetchPrice's
	// internal retries), so budget reads below meter actual enclave HTTP calls.
	sender := newTeeSender(runtime)

	// --- Step 1: fetch BTC/USD price ---
	// fetchPrice already retries quick transient failures internally
	// (fetchPriceMaxAttempts, back-to-back); this outer loop adds spaced
	// rounds with a 5s wait, preserving the pre-TEE resilience against
	// Chainlink hiccups.
	var priceData *PriceData
	for attempt := 1; attempt <= unifiedPriceMaxAttempts; attempt++ {
		pd, perr := fetchPrice(wc, logger, sender)
		if perr == nil && pd != nil {
			priceData = pd
			break
		}
		logger.Warn("price fetch failed; will retry",
			"attempt", attempt, "callsUsed", sender.Calls(), "error", perr)
		if isNonRetryablePriceFetchError(perr) {
			break
		}
		if attempt < unifiedPriceMaxAttempts {
			time.Sleep(unifiedRetryWaitSec * time.Second)
		}
	}
	if priceData == nil {
		return nil, fmt.Errorf("price fetch failed after %d attempts", unifiedPriceMaxAttempts)
	}

	currentPrice, _ := priceData.Price.Float64()
	quoteStamp := priceData.Stamp

	// --- Step 2: apply price adjustment if active ---
	currentPrice, adjusted := applyActiveAdjustment(wc, sender, currentPrice, quoteStamp, keys.SchnorrPubkey, logger)
	if adjusted {
		if err := validatePriceForEncoding(currentPrice); err != nil {
			return nil, fmt.Errorf("adjusted price out of bounds: %w", err)
		}
	}
	if currentPrice > float64(MaxPriceValue) {
		return nil, fmt.Errorf("current price %.2f exceeds uint32 max (%d)", currentPrice, MaxPriceValue)
	}
	basePrice := uint32(currentPrice)

	// --- Step 3: publish kind-10001 pending snapshot ---
	rateThold := wc.Config.LiquidationThold
	if rateThold == 0 {
		rateThold = 1.35
	}
	snapshot := PriceSnapshot{
		BasePrice:    int64(basePrice),
		BaseStamp:    quoteStamp,
		ChainNetwork: wc.Config.Network,
		OraclePubkey: keys.SchnorrPubkey,
		RateMin:      wc.Config.RateMin,
		RateMax:      wc.Config.RateMax,
		RateThold:    rateThold,
		StepSize:     wc.Config.StepSize,
	}
	snapshotJSON, err := json.Marshal(snapshot)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal price snapshot: %w", err)
	}
	pendingEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      PendingSnapshotKind,
		Tags:      [][]string{},
		Content:   string(snapshotJSON),
	}
	if err := signNostrEvent(pendingEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign pending snapshot event: %w", err)
	}
	if err := publishWithRetry(wc, sender, pendingEvent, unifiedSnapshotPubMaxAttempts, "kind-10001", logger); err != nil {
		return nil, err
	}

	// --- Step 4: build and publish the ladder ---
	liquidationThold := wc.Config.LiquidationThold
	if liquidationThold == 0 {
		liquidationThold = 1.35
	}
	quoteDomainPrefix := requestData.QuoteDomain
	if quoteDomainPrefix == "" {
		quoteDomainPrefix = requestData.Domain
	}

	var jobs []QuoteJob
	var minThold, maxThold float64
	for rawRate := requestData.RateMin; rawRate <= requestData.RateMax+0.0001; rawRate += requestData.StepSize {
		// Round to 2 decimals so wallets and oracle compute the same rate key
		// (otherwise float-accumulation drifts e.g. 3.95 → 3.949999999999959).
		rate := math.Round(rawRate*100) / 100
		tholdPrice := math.Ceil(float64(basePrice) * liquidationThold / rate)
		if tholdPrice > float64(MaxPriceValue) {
			logger.Warn("Skipping threshold price exceeding uint32 max", "rate", rate, "tholdPrice", tholdPrice)
			continue
		}
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

	type SignedEvent struct {
		Job       QuoteJob
		Event     *NostrEvent
		TholdHash string
	}
	var signedEvents []SignedEvent

	// Active ladder events expire quickly; revealed kind-1000 records are
	// published separately and remain persistent.
	expiresAt := strconv.FormatInt(quoteStamp+300, 10)

	for _, job := range jobs {
		contract, err := createPriceContract(
			wc.PrivateKey,
			keys.SchnorrPubkey,
			snapshot.ChainNetwork,
			basePrice,
			uint32(quoteStamp),
			uint32(job.TholdPrice),
		)
		if err != nil {
			logger.Warn("Failed to create contract", "rate", job.Rate, "error", err)
			continue
		}
		oracleSig, err := signSchnorr(keys.PrivateKey, contract.ContractID)
		if err != nil {
			logger.Warn("Failed to sign contract", "rate", job.Rate, "error", err)
			continue
		}
		eventData := PriceContractResponse{
			ChainNetwork: snapshot.ChainNetwork,
			OraclePubkey: keys.SchnorrPubkey,
			BasePrice:    int64(basePrice),
			BaseStamp:    quoteStamp,
			CommitHash:   contract.CommitHash,
			ContractID:   contract.ContractID,
			OracleSig:    oracleSig,
			TholdHash:    contract.TholdHash,
			TholdKey:     nil,
			TholdPrice:   int64(job.TholdPrice),
		}
		eventJSON, err := json.Marshal(eventData)
		if err != nil {
			logger.Warn("Failed to marshal event", "rate", job.Rate, "error", err)
			continue
		}
		// d-tag scopes to base_stamp so events from different snapshots
		// coexist on the relay instead of NIP-33-overwriting each other.
		// h-tag is what wallets query by (commit_hash).
		nostrEvent := &NostrEvent{
			PubKey:    keys.SchnorrPubkey,
			CreatedAt: quoteStamp,
			Kind:      NostrEventKindContract,
			Tags: [][]string{
				{"d", fmt.Sprintf("%d-%s", quoteStamp, strconv.FormatFloat(job.Rate, 'g', -1, 64))},
				{"h", contract.CommitHash},
				{"expires", expiresAt},
				{"expiration", expiresAt},
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

	var eventsToPublish []*NostrEvent
	for _, se := range signedEvents {
		eventsToPublish = append(eventsToPublish, se.Event)
	}

	// Publish chunks. We reserve unifiedCurrentPubMaxAttempts calls for the
	// final kind-10000 publish so we never run out of budget after the ladder.
	totalPublished := 0
	totalFailed := 0
	totalChunks := (len(eventsToPublish) + MaxEventsPerBatch - 1) / MaxEventsPerBatch

	for i := 0; i < len(eventsToPublish); i += MaxEventsPerBatch {
		end := i + MaxEventsPerBatch
		if end > len(eventsToPublish) {
			end = len(eventsToPublish)
		}
		chunk := eventsToPublish[i:end]
		chunkIdx := i / MaxEventsPerBatch
		chunksRemaining := totalChunks - chunkIdx - 1

		// Budget left for this chunk = total - calls used so far
		//                            - (chunks still to publish after this one)
		//                            - reserve for kind-10000 publish.
		maxAttemptsThisChunk := unifiedTotalCallBudget - sender.Calls() - chunksRemaining - unifiedCurrentPubMaxAttempts
		if maxAttemptsThisChunk < 1 {
			return nil, fmt.Errorf("budget exhausted before publishing chunk %d/%d (callsUsed=%d remaining=%d)", chunkIdx+1, totalChunks, sender.Calls(), chunksRemaining)
		}

		var chunkResp *BatchPublishResponse
		var lastErr error
		for attempt := 1; attempt <= maxAttemptsThisChunk; attempt++ {
			resp, err := publishEventsBatch(wc.Config, logger, sender, chunk)
			if err == nil && resp != nil && resp.Failed == 0 && resp.Published == len(chunk) {
				chunkResp = resp
				logger.Info("Chunk publish succeeded",
					"chunkIdx", chunkIdx, "attempt", attempt, "published", resp.Published, "callsUsed", sender.Calls())
				break
			}
			lastErr = err
			logger.Warn("Chunk publish failed; will retry if budget allows",
				"chunkIdx", chunkIdx, "attempt", attempt, "maxAttempts", maxAttemptsThisChunk,
				"callsUsed", sender.Calls(), "error", err)
			if attempt < maxAttemptsThisChunk {
				time.Sleep(unifiedRetryWaitSec * time.Second)
			}
		}
		if chunkResp == nil {
			return nil, fmt.Errorf("chunk %d/%d failed after %d attempt(s); callsUsed=%d; lastErr=%v",
				chunkIdx+1, totalChunks, maxAttemptsThisChunk, sender.Calls(), lastErr)
		}
		totalPublished += chunkResp.Published
		totalFailed += chunkResp.Failed
	}
	if totalFailed > 0 {
		return nil, fmt.Errorf("ladder reported %d failed events out of %d total (totalPublished=%d)", totalFailed, len(eventsToPublish), totalPublished)
	}
	if totalPublished != len(eventsToPublish) {
		return nil, fmt.Errorf("ladder published %d events but expected %d", totalPublished, len(eventsToPublish))
	}

	// --- Step 5: publish kind-10000 current snapshot ---
	currentEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      CurrentSnapshotKind,
		Tags:      [][]string{},
		Content:   string(snapshotJSON),
	}
	if err := signNostrEvent(currentEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("failed to sign current snapshot event: %w", err)
	}
	if err := publishWithRetry(wc, sender, currentEvent, unifiedCurrentPubMaxAttempts, "kind-10000", logger); err != nil {
		return nil, err
	}

	var tholdHashes []string
	for _, se := range signedEvents {
		tholdHashes = append(tholdHashes, se.TholdHash)
	}
	response := &GenerateQuotesResponse{
		QuotesCreated: totalPublished,
		CurrentPrice:  currentPrice,
		TholdHashes:   tholdHashes,
		GeneratedAt:   quoteStamp,
	}
	response.Range.MinThold = minThold
	response.Range.MaxThold = maxThold

	logger.Info("Unified cycle complete",
		"basePrice", snapshot.BasePrice,
		"baseStamp", snapshot.BaseStamp,
		"laddered", totalPublished,
		"adjusted", adjusted,
		"callsUsed", sender.Calls(),
	)
	return response, nil
}

// publishWithRetry publishes a single Nostr event up to maxAttempts times,
// incrementing *callsUsed for every relay call (success or failure). label is
// only used in logs to disambiguate kind-10001 vs kind-10000 failures.
func publishWithRetry(wc *WorkflowConfig, sender *teeSender, event *NostrEvent, maxAttempts int, label string, logger *slog.Logger) error {
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if sender.Calls() >= unifiedTotalCallBudget {
			return fmt.Errorf("%s publish: budget exhausted before attempt %d (callsUsed=%d)", label, attempt, sender.Calls())
		}
		resp, perr := publishEvent(wc.Config, logger, sender, event)
		if perr == nil && resp != nil && resp.Success {
			logger.Info("Published event",
				"label", label, "eventId", event.ID, "attempt", attempt, "callsUsed", sender.Calls())
			return nil
		}
		errMsg := ""
		if perr != nil {
			errMsg = perr.Error()
		} else if resp != nil {
			errMsg = resp.Message
		}
		logger.Warn("publish failed; will retry if budget allows",
			"label", label, "attempt", attempt, "callsUsed", sender.Calls(), "error", errMsg)
		if attempt < maxAttempts {
			time.Sleep(unifiedRetryWaitSec * time.Second)
		}
	}
	return fmt.Errorf("%s publish failed after %d attempts (callsUsed=%d)", label, maxAttempts, sender.Calls())
}

// --- Webhook Helpers ---

// sendWebhookCallback sends a best-effort POST notification to the callback URL.
func sendWebhookCallback(_ *Config, logger *slog.Logger, sendRequester httpSender, callbackURL string, event *NostrEvent, _ *PriceContractResponse, eventType string) {
	logger.Info("Sending webhook callback", "url", callbackURL, "eventType", eventType)

	callbackPayload := map[string]interface{}{
		"event_type": eventType,
		"event_id":   event.ID,
		"pubkey":     event.PubKey,
		"created_at": event.CreatedAt,
		"kind":       event.Kind,
		"tags":       event.Tags,
		"content":    event.Content,
		"sig":        event.Sig,
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal callback payload", "error", err)
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
		logger.Error("Webhook callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("Webhook callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("Webhook callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode, "body", string(resp.Body))
	}
}

// sendJSONCallback sends a best-effort JSON POST to the callback URL.
func sendJSONCallback(_ *Config, logger *slog.Logger, sendRequester httpSender, callbackURL string, domain string, eventType string, data interface{}) {
	logger.Info("Sending JSON callback", "url", callbackURL, "eventType", eventType, "domain", domain)

	callbackPayload := map[string]interface{}{
		"event_type": eventType,
		"event_id":   fmt.Sprintf("%s-%d", eventType, 0),
		"domain":     domain,
		"data":       data,
	}

	callbackJSON, err := json.Marshal(callbackPayload)
	if err != nil {
		logger.Error("Failed to marshal callback payload", "error", err)
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
		logger.Error("JSON callback failed", "url", callbackURL, "error", err)
		return
	}

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		logger.Info("JSON callback successful", "url", callbackURL, "status", resp.StatusCode)
	} else {
		logger.Warn("JSON callback returned non-2xx status", "url", callbackURL, "status", resp.StatusCode, "body", string(resp.Body))
	}
}

func adjustmentStatusFromRelay(wc *WorkflowConfig, sender httpSender, logger *slog.Logger, authorPubkey string, currentStamp int64) (*AdjustmentStatusResponse, error) {
	control, err := fetchAdjustmentControl(wc.Config, logger, sender, authorPubkey)
	if err != nil || control == nil {
		return &AdjustmentStatusResponse{
			Success: true,
			Active:  false,
			Message: "No active adjustment",
		}, nil
	}

	active := control.IsActive(currentStamp)
	msg := "Adjustment expired"
	if active {
		remaining := control.ExpiresAt - currentStamp
		msg = fmt.Sprintf("Active: %.2f%% adjustment, %d seconds remaining", control.Pct, remaining)
	}

	return &AdjustmentStatusResponse{
		Success:   true,
		Active:    active,
		Pct:       control.Pct,
		ExpiresAt: control.ExpiresAt,
		SetAt:     control.SetAt,
		Message:   msg,
	}, nil
}

func nextAdjustmentStamp(baseStamp int64, status *AdjustmentStatusResponse, minStamp int64) int64 {
	stamp := baseStamp
	if status != nil && status.SetAt >= stamp {
		stamp = status.SetAt + 1
	}
	if minStamp >= stamp {
		stamp = minStamp + 1
	}
	return stamp
}

func makeAdjustmentControl(pct float64, durationMinutes int, stamp int64) *PriceAdjustmentControl {
	expiresAt := stamp
	if pct != 0 {
		expiresAt = stamp + int64(durationMinutes*60)
	}
	return &PriceAdjustmentControl{
		Pct:       pct,
		ExpiresAt: expiresAt,
		SetAt:     stamp,
	}
}

func relayRejectedNewerEvent(message string) bool {
	lower := strings.ToLower(message)
	return strings.Contains(lower, "have newer event") || strings.Contains(lower, "replaced:")
}

func adjustmentStatusMatches(status *AdjustmentStatusResponse, pct float64) bool {
	if status == nil || !status.Success {
		return false
	}
	if pct == 0 {
		return !status.Active || status.Pct == 0
	}
	return status.Active && status.Pct == pct
}

func adjustmentResponseFromControl(control *PriceAdjustmentControl, active bool, message string) *PriceAdjustmentResponse {
	return &PriceAdjustmentResponse{
		Success:   true,
		Pct:       control.Pct,
		ExpiresAt: control.ExpiresAt,
		SetAt:     control.SetAt,
		Active:    active,
		Message:   message,
	}
}

func adjustmentResponseFromStatus(status *AdjustmentStatusResponse, message string) *PriceAdjustmentResponse {
	return &PriceAdjustmentResponse{
		Success:   true,
		Pct:       status.Pct,
		ExpiresAt: status.ExpiresAt,
		SetAt:     status.SetAt,
		Active:    status.Active,
		Message:   message,
	}
}

func publishAdjustmentControlOnce(wc *WorkflowConfig, sender httpSender, logger *slog.Logger, keys *KeyDerivation, control *PriceAdjustmentControl) (*RelayResponse, error) {
	return publishAdjustmentControl(wc.Config, logger, sender, keys, control, control.SetAt)
}

// setAdjustment handles the "adjust" action by publishing the active dev price
// adjustment control event to the relay.
func setAdjustment(wc *WorkflowConfig, runtime cre.TeeRuntime, reqData *PriceAdjustmentRequest) (*PriceAdjustmentResponse, error) {
	logger := runtime.Logger()
	logger.Info("Setting price adjustment", "pct", reqData.Pct, "durationMinutes", reqData.DurationMinutes)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	sender := newTeeSender(runtime)
	priceData, err := fetchPrice(wc, logger, sender)
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	currentStamp := priceData.Stamp
	status, err := adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
	if err != nil {
		return nil, fmt.Errorf("adjustment status lookup failed: %w", err)
	}
	control := makeAdjustmentControl(reqData.Pct, reqData.DurationMinutes, nextAdjustmentStamp(currentStamp, status, 0))

	relayResp, err := publishAdjustmentControlOnce(wc, sender, logger, keys, control)
	if err != nil {
		return nil, fmt.Errorf("failed to publish adjustment: %w", err)
	}
	if !relayResp.Success {
		if !relayRejectedNewerEvent(relayResp.Message) {
			return nil, fmt.Errorf("relay rejected adjustment: %s", relayResp.Message)
		}

		status, err = adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
		if err != nil {
			return nil, fmt.Errorf("adjustment status lookup after relay race failed: %w", err)
		}
		if adjustmentStatusMatches(status, reqData.Pct) {
			return adjustmentResponseFromStatus(status, fmt.Sprintf("Price adjustment of %.2f%% already active from newer event", reqData.Pct)), nil
		}

		control = makeAdjustmentControl(reqData.Pct, reqData.DurationMinutes, nextAdjustmentStamp(currentStamp, status, control.SetAt))
		relayResp, err = publishAdjustmentControlOnce(wc, sender, logger, keys, control)
		if err != nil {
			return nil, fmt.Errorf("failed to republish adjustment after relay race: %w", err)
		}
		if !relayResp.Success {
			status, statusErr := adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
			if statusErr == nil && adjustmentStatusMatches(status, reqData.Pct) {
				return adjustmentResponseFromStatus(status, fmt.Sprintf("Price adjustment of %.2f%% already active from newer event", reqData.Pct)), nil
			}
			return nil, fmt.Errorf("relay rejected adjustment: %s", relayResp.Message)
		}
	}

	logger.Info("Price adjustment set", "pct", reqData.Pct, "expiresAt", control.ExpiresAt, "durationMinutes", reqData.DurationMinutes)
	return adjustmentResponseFromControl(control, true, fmt.Sprintf("Price adjustment of %.2f%% set for %d minutes", reqData.Pct, reqData.DurationMinutes)), nil
}

// clearAdjustment handles the "clear_adjust" action by publishing a zeroed,
// expired control event.
func clearAdjustment(wc *WorkflowConfig, runtime cre.TeeRuntime) (*PriceAdjustmentResponse, error) {
	logger := runtime.Logger()
	logger.Info("Clearing price adjustment")

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	sender := newTeeSender(runtime)
	priceData, err := fetchPrice(wc, logger, sender)
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	currentStamp := priceData.Stamp
	status, err := adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
	if err != nil {
		return nil, fmt.Errorf("adjustment status lookup failed: %w", err)
	}
	control := makeAdjustmentControl(0, 0, nextAdjustmentStamp(currentStamp, status, 0))

	relayResp, err := publishAdjustmentControlOnce(wc, sender, logger, keys, control)
	if err != nil {
		return nil, fmt.Errorf("failed to clear adjustment: %w", err)
	}
	if !relayResp.Success {
		if !relayRejectedNewerEvent(relayResp.Message) {
			return nil, fmt.Errorf("relay rejected clear: %s", relayResp.Message)
		}

		status, err = adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
		if err != nil {
			return nil, fmt.Errorf("adjustment status lookup after relay race failed: %w", err)
		}
		if adjustmentStatusMatches(status, 0) {
			return adjustmentResponseFromStatus(status, "Price adjustment already cleared by newer event"), nil
		}

		control = makeAdjustmentControl(0, 0, nextAdjustmentStamp(currentStamp, status, control.SetAt))
		relayResp, err = publishAdjustmentControlOnce(wc, sender, logger, keys, control)
		if err != nil {
			return nil, fmt.Errorf("failed to republish clear after relay race: %w", err)
		}
		if !relayResp.Success {
			status, statusErr := adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, currentStamp)
			if statusErr == nil && adjustmentStatusMatches(status, 0) {
				return adjustmentResponseFromStatus(status, "Price adjustment already cleared by newer event"), nil
			}
			return nil, fmt.Errorf("relay rejected clear: %s", relayResp.Message)
		}
	}

	logger.Info("Price adjustment cleared")
	return adjustmentResponseFromControl(control, false, "Price adjustment cleared"), nil
}

// getAdjustmentStatus handles the "status" action.
func getAdjustmentStatus(wc *WorkflowConfig, runtime cre.TeeRuntime) (*AdjustmentStatusResponse, error) {
	logger := runtime.Logger()
	logger.Info("Checking adjustment status")

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	sender := newTeeSender(runtime)
	priceData, err := fetchPrice(wc, logger, sender)
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	return adjustmentStatusFromRelay(wc, sender, logger, keys.SchnorrPubkey, priceData.Stamp)
}

// applyActiveAdjustment checks for an active price adjustment and applies it.
// Returns the (possibly adjusted) price and whether an adjustment was applied.
func applyActiveAdjustment(wc *WorkflowConfig, sender httpSender, price float64, currentStamp int64, controlAuthor string, logger *slog.Logger) (float64, bool) {
	control, err := fetchAdjustmentControl(wc.Config, logger, sender, controlAuthor)
	if err != nil {
		logger.Warn("Failed to fetch adjustment control, using real price", "error", err)
		return price, false
	}
	statusResp := &AdjustmentStatusResponse{Active: false}
	if control != nil {
		statusResp = &AdjustmentStatusResponse{
			Active:    control.IsActive(currentStamp),
			Pct:       control.Pct,
			ExpiresAt: control.ExpiresAt,
		}
	}

	if !statusResp.Active {
		logger.Debug("No active price adjustment")
		return price, false
	}

	// SECURITY (H5): defense in depth — never trust the control event's pct.
	// Even though setAdjustment validates the bounds, the apply path must
	// independently reject an out-of-range pct (a stale, malformed, or otherwise
	// out-of-bounds control event) rather than pin the price arbitrarily far from
	// market. Fail safe to the real, unadjusted price.
	if statusResp.Pct < MinAdjustmentPct || statusResp.Pct > MaxAdjustmentPct {
		logger.Warn("Ignoring out-of-bounds price adjustment, using real price",
			"pct", statusResp.Pct,
			"minPct", MinAdjustmentPct,
			"maxPct", MaxAdjustmentPct,
		)
		return price, false
	}

	adjustedPrice := price * (1 + statusResp.Pct/100)
	logger.Info("Applying price adjustment",
		"originalPrice", price,
		"pct", statusResp.Pct,
		"adjustedPrice", adjustedPrice,
		"expiresAt", statusResp.ExpiresAt,
	)

	return adjustedPrice, true
}
