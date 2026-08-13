//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"math"

	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
)

// createQuote creates a new threshold commitment and publishes it as a Nostr event.
// Checks for an active price adjustment before using the price.
func createQuote(wc *WorkflowConfig, runtime cre.Runtime, requestData *HttpRequestData) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("Creating new quote", "domain", requestData.Domain, "tholdPrice", *requestData.TholdPrice)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current BTC/USD price with consensus
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	quoteStamp := priceData.Stamp

	// Check for active price adjustment
	currentPrice, adjusted := applyActiveAdjustment(wc, runtime, client, currentPrice, quoteStamp, logger)

	if adjusted {
		// Re-validate adjusted price is within bounds
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
		uint32(tholdPrice),
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
		TholdPrice:   int64(tholdPrice),
	}

	eventJSON, err := json.Marshal(priceContract)
	if err != nil {
		return nil, fmt.Errorf("event marshaling failed: %w", err)
	}

	nostrEvent := &NostrEvent{
		PubKey:    keys.SchnorrPubkey,
		CreatedAt: quoteStamp,
		Kind:      NostrEventKindThresholdCommitment,
		Tags: [][]string{
			{"d", contract.CommitHash},
			{"domain", requestData.Domain},
		},
		Content: string(eventJSON),
	}

	if err := signNostrEvent(nostrEvent, keys.PrivateKey); err != nil {
		return nil, fmt.Errorf("event signing failed: %w", err)
	}

	logger.Info("Created quote", "eventId", nostrEvent.ID, "tholdHash", contract.TholdHash, "adjusted", adjusted)

	// Publish to relay
	relayRespPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishEvent(wc.Config, log, sr, nostrEvent)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := relayRespPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("relay publish failed: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected event: %s", relayResp.Message)
	}

	// Send webhook callback if URL provided
	if requestData.CallbackURL != nil && *requestData.CallbackURL != "" {
		contract := &priceContract
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, nostrEvent, contract, "create")
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		_, _ = webhookPromise.Await()
	}

	return nostrEvent, nil
}

// fetchQuote looks up an existing quote on the relay by thold_hash and returns it.
func fetchQuote(wc *WorkflowConfig, runtime cre.Runtime, requestData *HttpRequestData) (*PriceEvent, error) {
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

	client := &http.Client{}
	fetchPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*BatchFetchResult, error) {
			return fetchEventByDTag(wc.Config, log, sr, tholdHash, oraclePubkey)
		},
		cre.ConsensusIdenticalAggregation[*BatchFetchResult](),
	)

	fetchResult, err := fetchPromise.Await()
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
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, *requestData.CallbackURL, &fetchResult.Event, &contract, "fetch")
				return &RelayResponse{Success: true, Message: "webhook sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		_, _ = webhookPromise.Await()
	}

	return priceEvent, nil
}

// evaluateQuotes batch evaluates quotes, revealing secrets for any that are breached.
// Checks for an active price adjustment before evaluating.
func evaluateQuotes(wc *WorkflowConfig, runtime cre.Runtime, requestData *EvaluateQuotesRequest) (*EvaluateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Evaluating quotes batch", "count", len(requestData.TholdHashes))

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current BTC/USD price
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	currentStamp := priceData.Stamp

	// Check for active price adjustment
	currentPrice, adjusted := applyActiveAdjustment(wc, runtime, client, currentPrice, currentStamp, logger)
	// SECURITY (M9): re-validate the adjusted price before it drives breach
	// decisions, matching createQuote/generateQuotes. The breach comparison
	// (currentPrice >= thold) feeds the liquidation reveal, so an out-of-range
	// adjusted price must not be used.
	if adjusted {
		if err := validatePriceForEncoding(currentPrice); err != nil {
			return nil, fmt.Errorf("adjusted price out of bounds: %w", err)
		}
	}

	logger.Info("Using price for evaluation", "currentPrice", currentPrice, "adjusted", adjusted)

	// PHASE 1: Fetch quotes one-by-one to avoid consensus decoding issues on nested slices.
	fetchResultMap := make(map[string]*BatchFetchResult, len(requestData.TholdHashes))
	for _, dTag := range requestData.TholdHashes {
		dTag := dTag
		fetchPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*BatchFetchResult, error) {
				return fetchEventByDTag(wc.Config, log, sr, dTag, keys.SchnorrPubkey)
			},
			cre.ConsensusIdenticalAggregation[*BatchFetchResult](),
		)

		fetchResp, fetchErr := fetchPromise.Await()
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
		logger.Info("Quote BREACHED", "tholdHash", tholdHash, "currentPrice", currentPrice, "tholdPrice", originalData.TholdPrice, "adjusted", adjusted)

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
			Kind:      NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", commitHash},
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

		batchPublishPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*BatchPublishResponse, error) {
				return publishEventsBatch(wc.Config, log, sr, breachEvents)
			},
			cre.ConsensusAggregationFromTags[*BatchPublishResponse](),
		)

		batchPublishResp, err := batchPublishPromise.Await()
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

// generateQuotesParallel auto-generates quotes across a rate range.
// Checks for an active price adjustment before generating.
func generateQuotesParallel(wc *WorkflowConfig, runtime cre.Runtime, requestData *GenerateQuotesRequest) (*GenerateQuotesResponse, error) {
	logger := runtime.Logger()
	logger.Info("Generating quotes", "rateMin", requestData.RateMin, "rateMax", requestData.RateMax, "stepSize", requestData.StepSize)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current BTC/USD price
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch failed: %w", err)
	}

	currentPrice, _ := priceData.Price.Float64()
	quoteStamp := priceData.Stamp

	// Check for active price adjustment
	currentPrice, adjusted := applyActiveAdjustment(wc, runtime, client, currentPrice, quoteStamp, logger)

	if adjusted {
		if err := validatePriceForEncoding(currentPrice); err != nil {
			return nil, fmt.Errorf("adjusted price out of bounds: %w", err)
		}
	}

	logger.Info("Using price for generation", "currentPrice", currentPrice, "adjusted", adjusted)

	quoteDomainPrefix := requestData.QuoteDomain
	if quoteDomainPrefix == "" {
		quoteDomainPrefix = requestData.Domain
	}

	var jobs []QuoteJob
	var minThold, maxThold float64

	if currentPrice > float64(MaxPriceValue) {
		return nil, fmt.Errorf("current price %.2f exceeds uint32 max (%d)", currentPrice, MaxPriceValue)
	}
	basePrice := uint32(currentPrice)

	liquidationThold := wc.Config.LiquidationThold
	if liquidationThold == 0 {
		liquidationThold = 1.35
	}

	for rawRate := requestData.RateMin; rawRate <= requestData.RateMax+0.0001; rawRate += requestData.StepSize {
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

	// Create all signed events
	type SignedEvent struct {
		Job       QuoteJob
		Event     *NostrEvent
		TholdHash string
	}
	var signedEvents []SignedEvent

	for _, job := range jobs {
		contract, err := createPriceContract(
			wc.PrivateKey,
			keys.SchnorrPubkey,
			wc.Config.Network,
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
			ChainNetwork: wc.Config.Network,
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

		nostrEvent := &NostrEvent{
			PubKey:    keys.SchnorrPubkey,
			CreatedAt: quoteStamp,
			Kind:      NostrEventKindThresholdCommitment,
			Tags: [][]string{
				{"d", contract.CommitHash},
				{"domain", job.Domain},
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

	// Publish in chunks
	var eventsToPublish []*NostrEvent
	for _, se := range signedEvents {
		eventsToPublish = append(eventsToPublish, se.Event)
	}

	totalPublished := 0
	totalFailed := 0

	for i := 0; i < len(eventsToPublish); i += MaxEventsPerBatch {
		end := i + MaxEventsPerBatch
		if end > len(eventsToPublish) {
			end = len(eventsToPublish)
		}
		chunk := eventsToPublish[i:end]

		chunkPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*BatchPublishResponse, error) {
				return publishEventsBatch(wc.Config, log, sr, chunk)
			},
			cre.ConsensusAggregationFromTags[*BatchPublishResponse](),
		)

		chunkResp, err := chunkPromise.Await()
		if err != nil {
			logger.Error("Chunk publish failed", "chunkStart", i, "error", err)
			totalFailed += len(chunk)
			continue
		}

		totalPublished += chunkResp.Published
		totalFailed += chunkResp.Failed
	}

	var tholdHashes []string
	for _, se := range signedEvents {
		tholdHashes = append(tholdHashes, se.TholdHash)
	}

	quotesCreated := totalPublished
	if quotesCreated < len(tholdHashes) {
		tholdHashes = tholdHashes[:quotesCreated]
	}

	response := &GenerateQuotesResponse{
		QuotesCreated: quotesCreated,
		CurrentPrice:  currentPrice,
		TholdHashes:   tholdHashes,
		GeneratedAt:   quoteStamp,
	}
	response.Range.MinThold = minThold
	response.Range.MaxThold = maxThold

	// Send callback to regulator
	if wc.Config.RegulatorCallbackURL != "" && len(signedEvents) > 0 {
		firstEvent := signedEvents[0]
		webhookPromise := http.SendRequest(wc, runtime, client,
			func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
				sendWebhookCallback(wc.Config, log, sr, wc.Config.RegulatorCallbackURL, firstEvent.Event, nil, "batch_generated")
				return &RelayResponse{Success: true, Message: "callback sent"}, nil
			},
			cre.ConsensusAggregationFromTags[*RelayResponse](),
		)
		_, _ = webhookPromise.Await()
	}

	return response, nil
}

// --- Price Adjustment Handlers ---

// setAdjustment handles the "adjust" action — sets a price adjustment on the relay.
func setAdjustment(wc *WorkflowConfig, runtime cre.Runtime, reqData *PriceAdjustmentRequest) (*PriceAdjustmentResponse, error) {
	logger := runtime.Logger()
	logger.Info("Setting price adjustment", "pct", reqData.Pct, "durationMinutes", reqData.DurationMinutes)

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current time from Chainlink (for consensus-safe timestamp)
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	currentStamp := priceData.Stamp
	expiresAt := currentStamp + int64(reqData.DurationMinutes*60)

	control := &PriceAdjustmentControl{
		Pct:       reqData.Pct,
		ExpiresAt: expiresAt,
		SetAt:     currentStamp,
	}

	// Publish control event to relay
	publishPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishAdjustmentControl(wc.Config, log, sr, keys, control, currentStamp)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := publishPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("failed to publish adjustment: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected adjustment: %s", relayResp.Message)
	}

	logger.Info("Price adjustment set", "pct", reqData.Pct, "expiresAt", expiresAt, "durationMinutes", reqData.DurationMinutes)

	return &PriceAdjustmentResponse{
		Success:   true,
		Pct:       reqData.Pct,
		ExpiresAt: expiresAt,
		SetAt:     currentStamp,
		Active:    true,
		Message:   fmt.Sprintf("Price adjustment of %.2f%% set for %d minutes", reqData.Pct, reqData.DurationMinutes),
	}, nil
}

// clearAdjustment handles the "clear_adjust" action — immediately disables the price adjustment.
func clearAdjustment(wc *WorkflowConfig, runtime cre.Runtime) (*PriceAdjustmentResponse, error) {
	logger := runtime.Logger()
	logger.Info("Clearing price adjustment")

	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("key derivation failed: %w", err)
	}
	defer keys.Zero()

	// Fetch current time from Chainlink
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	currentStamp := priceData.Stamp

	// Publish zeroed control event (pct=0, already expired)
	control := &PriceAdjustmentControl{
		Pct:       0,
		ExpiresAt: currentStamp, // Already expired
		SetAt:     currentStamp,
	}

	publishPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*RelayResponse, error) {
			return publishAdjustmentControl(wc.Config, log, sr, keys, control, currentStamp)
		},
		cre.ConsensusAggregationFromTags[*RelayResponse](),
	)

	relayResp, err := publishPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("failed to clear adjustment: %w", err)
	}

	if !relayResp.Success {
		return nil, fmt.Errorf("relay rejected clear: %s", relayResp.Message)
	}

	logger.Info("Price adjustment cleared")

	return &PriceAdjustmentResponse{
		Success:   true,
		Pct:       0,
		ExpiresAt: currentStamp,
		SetAt:     currentStamp,
		Active:    false,
		Message:   "Price adjustment cleared",
	}, nil
}

// getAdjustmentStatus handles the "status" action — returns the current adjustment state.
func getAdjustmentStatus(wc *WorkflowConfig, runtime cre.Runtime) (*AdjustmentStatusResponse, error) {
	logger := runtime.Logger()
	logger.Info("Checking adjustment status")

	// Fetch current time from Chainlink
	client := &http.Client{}
	priceDataPromise := http.SendRequest(wc, runtime, client, fetchPrice, cre.ConsensusAggregationFromTags[*PriceData]())
	priceData, err := priceDataPromise.Await()
	if err != nil {
		return nil, fmt.Errorf("price fetch for timestamp failed: %w", err)
	}

	currentStamp := priceData.Stamp

	// SECURITY (C2): pin the adjustment control author to the oracle's own pubkey.
	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to derive keys for adjustment author: %w", err)
	}
	controlAuthor := keys.SchnorrPubkey

	// Fetch control event from relay
	controlPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*AdjustmentStatusResponse, error) {
			control, err := fetchAdjustmentControl(wc.Config, log, sr, controlAuthor)
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
		},
		cre.ConsensusAggregationFromTags[*AdjustmentStatusResponse](),
	)

	return controlPromise.Await()
}

// applyActiveAdjustment checks for an active price adjustment and applies it.
// Returns the (possibly adjusted) price and whether an adjustment was applied.
func applyActiveAdjustment(wc *WorkflowConfig, runtime cre.Runtime, client *http.Client, price float64, currentStamp int64, logger *slog.Logger) (float64, bool) {
	// SECURITY (C2): pin the adjustment control author to the oracle's own pubkey.
	// On key-derivation failure, fail safe to the real (unadjusted) price.
	keys, err := deriveKeys(wc.PrivateKey)
	if err != nil {
		logger.Warn("Failed to derive keys for adjustment author, using real price", "error", err)
		return price, false
	}
	controlAuthor := keys.SchnorrPubkey

	controlPromise := http.SendRequest(wc, runtime, client,
		func(wc *WorkflowConfig, log *slog.Logger, sr *http.SendRequester) (*AdjustmentStatusResponse, error) {
			control, err := fetchAdjustmentControl(wc.Config, log, sr, controlAuthor)
			if err != nil || control == nil {
				return &AdjustmentStatusResponse{Active: false}, nil
			}
			return &AdjustmentStatusResponse{
				Active:    control.IsActive(currentStamp),
				Pct:       control.Pct,
				ExpiresAt: control.ExpiresAt,
			}, nil
		},
		cre.ConsensusAggregationFromTags[*AdjustmentStatusResponse](),
	)

	statusResp, err := controlPromise.Await()
	if err != nil {
		logger.Warn("Failed to fetch adjustment control, using real price", "error", err)
		return price, false
	}

	if !statusResp.Active {
		logger.Debug("No active price adjustment")
		return price, false
	}

	// SECURITY (H5/M9): defense in depth — never trust the control event's pct.
	// Reject an out-of-range pct (stale, malformed, or otherwise out-of-bounds)
	// rather than pin the price arbitrarily far from market. Fail safe to the
	// real, unadjusted price. (Mirrors hmac-dev/applyActiveAdjustment.)
	if statusResp.Pct < MinAdjustmentPct || statusResp.Pct > MaxAdjustmentPct {
		logger.Warn("Ignoring out-of-bounds price adjustment, using real price",
			"pct", statusResp.Pct,
			"minPct", MinAdjustmentPct,
			"maxPct", MaxAdjustmentPct,
		)
		return price, false
	}

	// Apply percentage adjustment
	adjustedPrice := price * (1 + statusResp.Pct/100)
	logger.Info("Applying price adjustment",
		"originalPrice", price,
		"pct", statusResp.Pct,
		"adjustedPrice", adjustedPrice,
		"expiresAt", statusResp.ExpiresAt,
	)

	return adjustedPrice, true
}

// --- Webhook Helpers ---

// QuoteJob represents a single quote to be generated
type QuoteJob struct {
	Rate       float64
	TholdPrice float64
	Domain     string
}

// sendWebhookCallback sends a best-effort POST notification to the callback URL.
func sendWebhookCallback(_ *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, event *NostrEvent, _ *PriceContractResponse, eventType string) {
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
func sendJSONCallback(_ *Config, logger *slog.Logger, sendRequester *http.SendRequester, callbackURL string, domain string, eventType string, data interface{}) {
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
