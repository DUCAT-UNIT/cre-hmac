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

// DUCAT workflow entry point for CRE/WASM execution
// Routes HTTP triggers to CREATE or EVALUATE handlers

const (
	SecretPrivateKey   = "private_key"
	SecretClientSecret = "client_secret"
)

// WorkflowConfig holds both config and secrets (fetched at runtime)
// SECURITY: Secrets are stored as []byte to enable proper zeroing after use
type WorkflowConfig struct {
	Config           *Config
	PrivateKey       string // Hex-encoded private key (for compatibility with existing code)
	PrivateKeyBytes  []byte // Raw private key bytes - ZERO AFTER USE
	ClientSecret     string // Client secret for API auth
	ClientSecretBytes []byte // Raw client secret bytes - ZERO AFTER USE
}

// ZeroSecrets zeros all secret byte arrays in the WorkflowConfig
// SECURITY: Call this after cryptographic operations to minimize secret exposure window
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
	Action string `json:"action"` // "create", "evaluate"
}

// onHttpTrigger routes requests based on action parameter
// action=create OR thold_price -> CREATE new quote
// onHttpTrigger routes incoming HTTP payloads to either quote creation or batch evaluation.
// It requires a non-empty payload input and fetches runtime secrets before routing.
// If the top-level `"action"` field equals `"evaluate"`, it parses and validates an EvaluateQuotesRequest and forwards it to evaluateQuotes.
// Otherwise it parses and validates HttpRequestData and, when a TholdPrice is present, forwards it to createQuote.
// Returns the handler response on success or an error if input is missing, secrets cannot be obtained, parsing/validation fail, or required fields (for example `thold_price` for creation) are absent.
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
	// SECURITY: Zero secrets after handler completes
	defer wc.ZeroSecrets()

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
// onCronTrigger handles a scheduled cron firing to generate quotes using the workflow configuration.
// It fetches runtime secrets, constructs a GenerateQuotesRequest from RateMin, RateMax, StepSize and a domain derived from QuoteDomain (or "auto-gen") combined with the scheduled Unix timestamp, validates the request, and invokes quote generation, returning the generated quotes response or an error.
func onCronTrigger(config *Config, runtime cre.Runtime, trigger *cron.Payload) (*GenerateQuotesResponse, error) {
	logger := runtime.Logger()
	scheduledTime := trigger.ScheduledExecutionTime.AsTime()
	logger.Info("Cron trigger fired for quote generation", "scheduledTime", scheduledTime)

	// Fetch secrets from runtime
	wc, err := buildWorkflowConfig(config, runtime)
	if err != nil {
		return nil, err
	}
	// SECURITY: Zero secrets after handler completes
	defer wc.ZeroSecrets()

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

// buildWorkflowConfig constructs a WorkflowConfig by retrieving required runtime secrets.
// It returns a WorkflowConfig populated with the provided Config and the fetched
// private_key and client_secret. An error is returned if a secret cannot be fetched,
// if private_key is not exactly 64 characters, or if client_secret is empty.
// SECURITY: The returned WorkflowConfig contains raw secret bytes - caller MUST call
// ZeroSecrets() when done with cryptographic operations.
func buildWorkflowConfig(config *Config, runtime cre.Runtime) (*WorkflowConfig, error) {
	logger := runtime.Logger()

	// Fetch secrets from runtime
	privateKeyReq := &pb.SecretRequest{Id: SecretPrivateKey}
	privateKeySecret, err := runtime.GetSecret(privateKeyReq).Await()
	if err != nil {
		logger.Error("Failed to fetch private_key secret", "error", err)
		return nil, ErrSecretFetchFailed("private_key", err)
	}
	if len(privateKeySecret.Value) != 64 {
		logger.Error("Invalid private_key length", "expected", 64, "got", len(privateKeySecret.Value))
		return nil, ErrValidationFailed("private_key")
	}

	// Decode private key to bytes immediately
	privateKeyBytes, err := hex.DecodeString(privateKeySecret.Value)
	if err != nil {
		logger.Error("Invalid private_key hex format", "error", err)
		return nil, ErrValidationFailed("private_key")
	}

	clientSecretReq := &pb.SecretRequest{Id: SecretClientSecret}
	clientSecretSecret, err := runtime.GetSecret(clientSecretReq).Await()
	if err != nil {
		// Zero private key bytes before returning error
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
		logger.Error("Failed to fetch client_secret secret", "error", err)
		return nil, ErrSecretFetchFailed("client_secret", err)
	}
	if clientSecretSecret.Value == "" {
		// Zero private key bytes before returning error
		for i := range privateKeyBytes {
			privateKeyBytes[i] = 0
		}
		logger.Error("client_secret is empty")
		return nil, ErrValidationFailed("client_secret")
	}

	return &WorkflowConfig{
		Config:            config,
		PrivateKey:        privateKeySecret.Value,
		PrivateKeyBytes:   privateKeyBytes,
		ClientSecret:      clientSecretSecret.Value,
		ClientSecretBytes: []byte(clientSecretSecret.Value),
	}, nil
}

// InitWorkflow initializes the DUCAT workflow using the provided configuration, logger, and secrets provider.
// It validates the config and returns an error if validation fails. It configures an HTTP trigger that requires
// JWT authentication for a predefined ECDSA EVM public key, assembles the workflow handlers, and (if
// CronSchedule is set) adds a cron trigger to generate quotes on the configured schedule.
func InitWorkflow(config *Config, logger *slog.Logger, secrets cre.SecretsProvider) (cre.Workflow[*Config], error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return cre.Workflow[*Config]{}, fmt.Errorf("config validation failed: %w", err)
	}

	logger.Info("DUCAT workflow initialized", "network", config.Network, "relayUrl", config.RelayURL)

	// Configure HTTP trigger with authorized Ethereum address from config
	// SECURITY: AuthorizedKey is validated during config.Validate() to ensure it's a valid
	// Ethereum address format (0x + 40 hex chars). JWT authentication is enforced by the CRE
	// runtime - only requests signed by this address will be accepted.
	httpConfig := &http.Config{
		AuthorizedKeys: []*http.AuthorizedKey{
			{
				Type:      http.KeyType_KEY_TYPE_ECDSA_EVM,
				PublicKey: config.AuthorizedKey,
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