//go:build wasip1

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"

	pb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/scheduler/cron"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
)

// DUCAT DEV workflow entry point for CRE/WASM execution
// Same as production workflow, plus price adjustment control actions:
//   action=adjust      → set a % price adjustment for N minutes
//   action=clear_adjust → immediately clear any active adjustment
//   action=status      → check current adjustment state

const (
	SecretPrivateKey   = "private_key"
	SecretClientSecret = "client_secret"
)

// WorkflowConfig holds both config and secrets (fetched at runtime)
type WorkflowConfig struct {
	Config            *Config
	PrivateKey        string
	PrivateKeyBytes   []byte
	ClientSecret      string
	ClientSecretBytes []byte
}

// ZeroSecrets zeros all secret byte arrays
func (wc *WorkflowConfig) ZeroSecrets() {
	if wc.PrivateKeyBytes != nil {
		for i := range wc.PrivateKeyBytes {
			wc.PrivateKeyBytes[i] = 0
		}
	}
	if wc.ClientSecretBytes != nil {
		for i := range wc.ClientSecretBytes {
			wc.ClientSecretBytes[i] = 0
		}
	}
}

// GenericHttpRequest is a wrapper to parse action field first
type GenericHttpRequest struct {
	Action string `json:"action"`
}

func sendEvaluateErrorCallback(wc *WorkflowConfig, runtime cre.TeeRuntime, callbackURL string, req *EvaluateQuotesRequest, evalErr error) {
	if callbackURL == "" || req == nil || evalErr == nil {
		return
	}

	errMsg := evalErr.Error()
	results := make([]QuoteEvaluationResult, len(req.TholdHashes))
	for i, hash := range req.TholdHashes {
		resultHash := hash
		results[i] = QuoteEvaluationResult{
			TholdHash: resultHash,
			Status:    "error",
			Error:     &errMsg,
		}
	}

	response := &EvaluateQuotesResponse{
		Results:      results,
		CurrentPrice: 0,
		EvaluatedAt:  runtime.Now().Unix(),
	}
	response.ComputeSummary()

	trackingDomain := "eval-error"
	if len(req.TholdHashes) > 0 {
		first := req.TholdHashes[0]
		if len(first) >= 8 {
			trackingDomain = fmt.Sprintf("eval-%s", first[:8])
		} else if first != "" {
			trackingDomain = fmt.Sprintf("eval-%s", first)
		}
	}

	sendJSONCallback(wc.Config, runtime.Logger(), newTeeSender(runtime), callbackURL, trackingDomain, "evaluate", response)
}

// onHttpTrigger routes requests based on action parameter.
// Supports all production actions plus dev-only adjustment control:
//
//	action=adjust       → set price adjustment
//	action=clear_adjust → clear price adjustment
//	action=status       → get adjustment status
//	action=evaluate     → batch evaluate quotes
//	thold_price present → create new quote
func onHttpTrigger(config *Config, runtime cre.TeeRuntime, payload *http.Payload) (interface{}, error) {
	logger := runtime.Logger()
	logger.Info("HTTP trigger received (dev)")

	if payload.Input == nil || len(payload.Input) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	// Fetch secrets from runtime
	wc, err := buildWorkflowConfig(config, runtime)
	if err != nil {
		return nil, err
	}
	defer wc.ZeroSecrets()

	// Parse action field
	var genericReq GenericHttpRequest
	_ = json.Unmarshal(payload.Input, &genericReq)

	// Route based on action
	switch genericReq.Action {
	case "adjust":
		if !config.EnablePriceAdjustment {
			return nil, fmt.Errorf("price adjustment controls are disabled for this deployment")
		}
		var adjustReq PriceAdjustmentRequest
		if err := json.Unmarshal(payload.Input, &adjustReq); err != nil {
			return nil, fmt.Errorf("invalid adjust request format: %w", err)
		}
		if err := adjustReq.Validate(); err != nil {
			return nil, fmt.Errorf("adjust validation failed: %w", err)
		}
		logger.Info("Routing to setAdjustment", "pct", adjustReq.Pct, "duration", adjustReq.DurationMinutes)
		return setAdjustment(wc, runtime, &adjustReq)

	case "clear_adjust":
		if !config.EnablePriceAdjustment {
			return nil, fmt.Errorf("price adjustment controls are disabled for this deployment")
		}
		logger.Info("Routing to clearAdjustment")
		return clearAdjustment(wc, runtime)

	case "status":
		logger.Info("Routing to getAdjustmentStatus")
		return getAdjustmentStatus(wc, runtime)

	case "evaluate":
		var evalReq EvaluateQuotesRequest
		if err := json.Unmarshal(payload.Input, &evalReq); err != nil {
			return nil, fmt.Errorf("invalid evaluate request format: %w", err)
		}

		callbackURL := ""
		if evalReq.CallbackURL != nil {
			callbackURL = *evalReq.CallbackURL
		}

		if err := evalReq.Validate(); err != nil {
			sendEvaluateErrorCallback(wc, runtime, callbackURL, &evalReq, err)
			return nil, fmt.Errorf("validation failed: %w", err)
		}

		logger.Info("Routing to evaluateQuotes", "tholdHashCount", len(evalReq.TholdHashes))
		evalResp, err := evaluateQuotes(wc, runtime, &evalReq)
		if err != nil {
			logger.Error("evaluateQuotes failed", "error", err)
			sendEvaluateErrorCallback(wc, runtime, callbackURL, &evalReq, err)
			return nil, err
		}
		return evalResp, nil

	default:
		// Create quote (legacy routing based on thold_price)
		var requestData HttpRequestData
		if err := json.Unmarshal(payload.Input, &requestData); err != nil {
			return nil, fmt.Errorf("invalid request format: %w", err)
		}
		if err := requestData.Validate(); err != nil {
			return nil, fmt.Errorf("validation failed: %w", err)
		}

		logger.Info("Parsed request", "domain", requestData.Domain, "hasTholdPrice", requestData.TholdPrice != nil)

		if requestData.TholdPrice != nil {
			return createQuote(wc, runtime, &requestData)
		}

		if requestData.TholdHash != nil {
			return fetchQuote(wc, runtime, &requestData)
		}

		return nil, fmt.Errorf("invalid request: must provide thold_price for create, thold_hash for fetch, or action=evaluate/adjust/clear_adjust/status")
	}
}

// onCronTrigger runs the unified dev cycle: fetch Chainlink price → publish
// kind-10001 pending snapshot → publish full kind-30000 ladder → publish
// kind-10000 current snapshot. All in one execution under the 20-call CRE
// budget. See runUnifiedCycle for the call accounting.
func onCronTrigger(config *Config, runtime cre.TeeRuntime, trigger *cron.Payload) (interface{}, error) {
	logger := runtime.Logger()
	scheduledTime := trigger.ScheduledExecutionTime.AsTime()
	logger.Info("Cron trigger fired (dev-unified)",
		"scheduledTime", scheduledTime,
		"rateMin", config.RateMin, "rateMax", config.RateMax,
	)

	wc, err := buildWorkflowConfig(config, runtime)
	if err != nil {
		return nil, err
	}
	defer wc.ZeroSecrets()

	quoteDomain := config.QuoteDomain
	if quoteDomain == "" {
		quoteDomain = "auto-gen"
	}

	genReq := &GenerateQuotesRequest{
		RateMin:     config.RateMin,
		RateMax:     config.RateMax,
		StepSize:    config.StepSize,
		Domain:      fmt.Sprintf("%s-%d", quoteDomain, scheduledTime.Unix()),
		QuoteDomain: quoteDomain,
	}
	if err := genReq.Validate(); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	return runUnifiedCycle(wc, runtime, genReq)
}

// buildWorkflowConfig constructs a WorkflowConfig by retrieving required runtime secrets.
// Under cre.HandlerInTee the secrets are threshold-decrypted by the Vault DON
// directly inside the enclave — plaintext never exists in Workflow DON node
// memory. Both secrets are fetched in a SINGLE batched GetSecrets call: one
// relay-DON/Vault-DON quorum round instead of two (a second sequential
// secrets round was observed failing quorum in the confidential beta).
func buildWorkflowConfig(config *Config, runtime cre.TeeRuntime) (*WorkflowConfig, error) {
	logger := runtime.Logger()

	secrets, err := runtime.GetSecrets([]*pb.SecretRequest{
		{Id: SecretPrivateKey},
		{Id: SecretClientSecret},
	}).Await()
	if err != nil {
		logger.Error("Failed to fetch secrets batch", "error", err)
		return nil, fmt.Errorf("failed to fetch secrets: %w", err)
	}

	var privateKeyValue, clientSecretValue string
	for _, s := range secrets {
		if s == nil {
			continue
		}
		switch s.Id {
		case SecretPrivateKey:
			privateKeyValue = s.Value
		case SecretClientSecret:
			clientSecretValue = s.Value
		}
	}
	if privateKeyValue == "" {
		return nil, fmt.Errorf("private_key missing from secrets response")
	}
	if clientSecretValue == "" {
		return nil, fmt.Errorf("client_secret missing from secrets response")
	}

	if len(privateKeyValue) != 64 {
		return nil, fmt.Errorf("private_key must be 64 hex characters, got %d", len(privateKeyValue))
	}

	privateKeyBytes, err := hex.DecodeString(privateKeyValue)
	if err != nil {
		return nil, fmt.Errorf("private_key is not valid hex: %w", err)
	}

	return &WorkflowConfig{
		Config:            config,
		PrivateKey:        privateKeyValue,
		PrivateKeyBytes:   privateKeyBytes,
		ClientSecret:      clientSecretValue,
		ClientSecretBytes: []byte(clientSecretValue),
	}, nil
}

// InitWorkflow initializes the DUCAT DEV workflow.
func InitWorkflow(config *Config, logger *slog.Logger, secrets cre.SecretsProvider) (cre.Workflow[*Config], error) {
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return cre.Workflow[*Config]{}, fmt.Errorf("config validation failed: %w", err)
	}

	logger.Info("DUCAT DEV workflow initialized", "network", config.Network, "relayUrl", config.RelayURL)

	httpConfig := &http.Config{
		AuthorizedKeys: []*http.AuthorizedKey{
			{
				Type:      http.KeyType_KEY_TYPE_ECDSA_EVM,
				PublicKey: config.AuthorizedKey,
			},
		},
	}

	// Confidential Workflows: both handlers execute inside an attested TEE.
	// Triggers still fire on the Workflow DON (trigger payloads are visible to
	// node operators); only the callback bodies run in the enclave.
	handlers := cre.Workflow[*Config]{
		cre.HandlerInTee(http.Trigger(httpConfig), onHttpTrigger, teeConstraint()),
	}

	if config.CronSchedule != "" {
		logger.Info("Configuring cron trigger (dev)",
			"schedule", config.CronSchedule,
			"rateMin", config.RateMin,
			"rateMax", config.RateMax,
			"stepSize", config.StepSize,
		)

		cronTrigger := cron.Trigger(&cron.Config{Schedule: config.CronSchedule})
		handlers = append(handlers, cre.HandlerInTee(cronTrigger, onCronTrigger, teeConstraint()))
	}

	return handlers, nil
}

func main() {
	wasm.NewRunner(cre.ParseJSON[Config]).Run(InitWorkflow)
}
