//go:build wasip1

package main

import (
	"encoding/json"
	"fmt"
	"log/slog"

	pb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
)

// DUCAT workflow entry point for CRE/WASM execution
// Routes HTTP triggers to CREATE or CHECK handlers

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

// onHttpTrigger routes requests based on parameters
// thold_price -> CREATE new quote
// thold_hash -> CHECK existing quote
func onHttpTrigger(config *Config, runtime cre.Runtime, payload *http.Payload) (*NostrEvent, error) {
	logger := runtime.Logger()
	logger.Info("HTTP trigger received")

	if payload.Input == nil || len(payload.Input) == 0 {
		return nil, fmt.Errorf("no input provided")
	}

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

	// Build workflow config with secrets
	wc := &WorkflowConfig{
		Config:       config,
		PrivateKey:   privateKeySecret.Value,
		ClientSecret: clientSecretSecret.Value,
	}

	// Parse request data
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

	logger.Info("Parsed request", "domain", requestData.Domain, "hasTholdPrice", requestData.TholdPrice != nil, "hasTholdHash", requestData.TholdHash != nil)

	// Route to appropriate handler
	if requestData.TholdPrice != nil {
		// Create new quote
		return createQuote(wc, runtime, &requestData)
	} else if requestData.TholdHash != nil {
		// Check existing quote
		return checkQuote(wc, runtime, &requestData)
	}

	return nil, fmt.Errorf("invalid request: must provide either thold_price or thold_hash")
}

// InitWorkflow initializes workflow with config validation
func InitWorkflow(config *Config, logger *slog.Logger, secrets cre.SecretsProvider) (cre.Workflow[*Config], error) {
	// Validate configuration
	if err := config.Validate(); err != nil {
		logger.Error("Configuration validation failed", "error", err)
		return cre.Workflow[*Config]{}, fmt.Errorf("config validation failed: %w", err)
	}

	logger.Info("DUCAT workflow initialized", "network", config.Network, "relayUrl", config.RelayURL)

	return cre.Workflow[*Config]{
		cre.Handler(http.Trigger(&http.Config{}), onHttpTrigger),
	}, nil
}

// main is the WASM entry point
func main() {
	wasm.NewRunner(cre.ParseJSON[Config]).Run(InitWorkflow)
}
