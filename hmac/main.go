//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	pb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/scheduler/cron"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
)

// DUCAT workflow entry point for CRE/WASM execution
// Routes HTTP triggers to CREATE or EVALUATE handlers

const (
	SecretPrivateKey  = "private_key"
	SecretClientSecret = "client_secret"
)

// WorkflowConfig holds both config and secrets (fetched at runtime)
type WorkflowConfig struct {
	Config       *Config
	PrivateKey   string
	ClientSecret string
}

// GenericHttpRequest is a wrapper to parse action field first
type GenericHttpRequest struct {
	Action string `json:"action"` // "create", "evaluate"
}

// onHttpTrigger routes requests based on action parameter
// action=create OR thold_price -> CREATE new quote
// action=evaluate -> EVALUATE batch quotes (with breach detection)
func onHttpTrigger(config *Config, runtime cre.Runtime, payload *http.Payload) (interface{}, error) {
	logger := runtime.Logger()
	logger.Info("HTTP trigger received")

	if payload.Input == nil || len(payload.Input) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

	// Fetch secrets from runtime
	wc, err := buildWorkflowConfig(config, runtime)
	if err != nil {
		return nil, err
	}

	// First, check if there's an explicit action field
	var genericReq GenericHttpRequest
	_ = json.Unmarshal(payload.Input, &genericReq)

	// Route based on action field
	switch genericReq.Action {
	case "evaluate":
		// Batch evaluate quotes
		var evalReq EvaluateQuotesRequest
		if err := json.Unmarshal(payload.Input, &evalReq); err != nil {
			logger.Error("Failed to parse evaluate request", "error", err)
			return nil, fmt.Errorf("invalid evaluate request format: %w", err)
		}
		if err := evalReq.Validate(); err != nil {
			logger.Error("Evaluate request validation failed", "error", err)
			return nil, fmt.Errorf("validation failed: %w", err)
		}
		logger.Info("Routing to evaluateQuotes", "tholdHashCount", len(evalReq.TholdHashes))
		return evaluateQuotes(wc, runtime, &evalReq)

	default:
		// Create quote (legacy routing based on thold_price)
		var requestData HttpRequestData
		if err := json.Unmarshal(payload.Input, &requestData); err != nil {
			logger.Error("Failed to parse request", "error", err)
			return nil, fmt.Errorf("invalid request format: %w", err)
		}

		// Validate request
		if err := requestData.Validate(); err != nil {
			logger.Error("Request validation failed", "error", err)
			return nil, fmt.Errorf("validation failed: %w", err)
		}

		logger.Info("Parsed request", "domain", requestData.Domain, "hasTholdPrice", requestData.TholdPrice != nil)

		if requestData.TholdPrice != nil {
			return createQuote(wc, runtime, &requestData)
		}

		return nil, fmt.Errorf("invalid request: must provide thold_price for create or action=evaluate")
	}
}

// onCronTrigger handles scheduled quote generation
// Fires based on cron_schedule in config
// Generates quotes from rate_min to rate_max at step_size intervals
func onCronTrigger(config *Config, runtime cre.Runtime, trigger *cron.Payload) (*GenerateQuotesResponse, error) {
	logger := runtime.Logger()
	scheduledTime := trigger.ScheduledExecutionTime.AsTime()
	logger.Info("Cron trigger fired for quote generation", "scheduledTime", scheduledTime)

	// Fetch secrets from runtime
	wc, err := buildWorkflowConfig(config, runtime)
	if err != nil {
		return nil, err
	}

	// Use generation parameters from config
	// Use QuoteDomain from config, or default to "auto-gen"
	quoteDomain := config.QuoteDomain
	if quoteDomain == "" {
		quoteDomain = "auto-gen"
	}

	// Create request from config parameters
	genReq := &GenerateQuotesRequest{
		RateMin:     config.RateMin,
		RateMax:     config.RateMax,
		StepSize:    config.StepSize,
		Domain:      fmt.Sprintf("%s-%d", quoteDomain, scheduledTime.Unix()),
		QuoteDomain: quoteDomain,
	}

	// Validate request
	if err := genReq.Validate(); err != nil {
		logger.Error("Generate request validation failed", "error", err)
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	logger.Info("Starting quote generation",
		"rateMin", genReq.RateMin,
		"rateMax", genReq.RateMax,
		"stepSize", genReq.StepSize,
		"quoteDomain", quoteDomain,
	)

	return generateQuotesParallel(wc, runtime, genReq)
}

// buildWorkflowConfig fetches secrets and builds WorkflowConfig
func buildWorkflowConfig(config *Config, runtime cre.Runtime) (*WorkflowConfig, error) {
	logger := runtime.Logger()

	// Fetch secrets from runtime
	privateKeyReq := &pb.SecretRequest{Id: SecretPrivateKey}
	privateKeySecret, err := runtime.GetSecret(privateKeyReq).Await()
	if err != nil {
		logger.Error("Failed to fetch private_key secret", "error", err)
		return nil, fmt.Errorf("failed to fetch private_key: %w", err)
	}
	if len(privateKeySecret.Value) != 64 {
		return nil, fmt.Errorf("private_key must be 64 hex characters, got %d", len(privateKeySecret.Value))
	}

	clientSecretReq := &pb.SecretRequest{Id: SecretClientSecret}
	clientSecretSecret, err := runtime.GetSecret(clientSecretReq).Await()
	if err != nil {
		logger.Error("Failed to fetch client_secret secret", "error", err)
		return nil, fmt.Errorf("failed to fetch client_secret: %w", err)
	}
	if clientSecretSecret.Value == "" {
		return nil, fmt.Errorf("client_secret cannot be empty")
	}

	return &WorkflowConfig{
		Config:       config,
		PrivateKey:   privateKeySecret.Value,
		ClientSecret: clientSecretSecret.Value,
	}, nil
}

// InitWorkflow initializes workflow with config validation
func InitWorkflow(config *Config, logger *slog.Logger, secrets cre.SecretsProvider) (cre.Workflow[*Config], error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return cre.Workflow[*Config]{}, fmt.Errorf("config validation failed: %w", err)
	}

	logger.Info("DUCAT workflow initialized", "network", config.Network, "relayUrl", config.RelayURL)

	// Configure HTTP trigger with authorized Ethereum address
	// This allows JWT authentication from the specified address
	httpConfig := &http.Config{
		AuthorizedKeys: []*http.AuthorizedKey{
			{
				Type:      http.KeyType_KEY_TYPE_ECDSA_EVM,
				PublicKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82",
			},
		},
	}

	// Build workflow handlers
	handlers := cre.Workflow[*Config]{
		cre.Handler(http.Trigger(httpConfig), onHttpTrigger),
	}

	// Add Cron trigger for quote generation if schedule is configured
	if config.CronSchedule != "" {
		logger.Info("Configuring cron trigger for quote generation",
			"schedule", config.CronSchedule,
			"rateMin", config.RateMin,
			"rateMax", config.RateMax,
			"stepSize", config.StepSize,
		)

		cronTrigger := cron.Trigger(&cron.Config{Schedule: config.CronSchedule})
		handlers = append(handlers, cre.Handler(cronTrigger, onCronTrigger))
	}

	return handlers, nil
}

// main is the WASM entry point
func main() {
	wasm.NewRunner(cre.ParseJSON[Config]).Run(InitWorkflow)
}
