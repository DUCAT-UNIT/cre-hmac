//go:build ignore

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"ducat/internal/ethsign"

	"github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
)

const (
	GatewayURL = "https://01.gateway.zone-a.cre.chain.link"
)

// JSONRPCRequest represents the workflow execution request
type JSONRPCRequest struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      string                 `json:"id"`
	Method  string                 `json:"method"`
	Params  map[string]interface{} `json:"params"`
}

// JSONRPCResponse represents the gateway response
type JSONRPCResponse struct {
	JSONRPC string                 `json:"jsonrpc"`
	ID      string                 `json:"id"`
	Method  string                 `json:"method,omitempty"`
	Result  map[string]interface{} `json:"result,omitempty"`
	Error   *JSONRPCError          `json:"error,omitempty"`
}

type JSONRPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// main is the CLI entry point that constructs and sends a JWT-authenticated JSON-RPC
// request to the configured gateway to trigger a workflow execution.
// It parses command-line flags (workflow-id, domain, op, thold-price, thold-hash, callback-url),
// validates inputs, loads an ECDSA private key from DUCAT_PRIVATE_KEY, derives an Ethereum-style
// address, and builds the workflow input for either a "create" (includes thold_price) or
// "check" (includes thold_hash) operation. The function marshals the request with stable key
// ordering, computes a SHA-256 digest, produces an ETH-style signed JWT containing that digest,
// sends the request with the JWT as a Bearer token, and prints the gateway response and a
// workflow tracking URL when available.
func main() {
	// Command-line flags
	workflowID := flag.String("workflow-id", "", "Workflow ID (64 hex characters, no 0x prefix)")
	domain := flag.String("domain", "", "Domain name for the quote")
	tholdPrice := flag.String("thold-price", "", "Threshold price for CREATE operation (e.g., '94000.00')")
	tholdHash := flag.String("thold-hash", "", "Threshold hash for CHECK operation (40 hex chars)")
	operation := flag.String("op", "", "Operation: 'create' or 'check'")
	callbackURL := flag.String("callback-url", "", "Optional webhook URL to receive result notification")

	flag.Parse()

	// Validate inputs
	if *workflowID == "" {
		fmt.Println("Error: --workflow-id is required")
		flag.Usage()
		os.Exit(1)
	}
	if *domain == "" {
		fmt.Println("Error: --domain is required")
		flag.Usage()
		os.Exit(1)
	}
	if *operation == "" {
		fmt.Println("Error: --op is required (create or check)")
		flag.Usage()
		os.Exit(1)
	}

	// Load private key from environment
	privateKeyHex := os.Getenv("DUCAT_PRIVATE_KEY")
	if privateKeyHex == "" {
		fmt.Println("Error: DUCAT_PRIVATE_KEY environment variable not set")
		os.Exit(1)
	}

	// Remove 0x prefix if present
	privateKeyHex = strings.TrimPrefix(privateKeyHex, "0x")

	// Parse private key using go-ethereum crypto
	privKey, err := crypto.HexToECDSA(privateKeyHex)
	if err != nil {
		fmt.Printf("Error parsing private key: %v\n", err)
		os.Exit(1)
	}

	// Derive Ethereum address using shared package
	address := ethsign.PubKeyToAddress(&privKey.PublicKey)
	fmt.Printf("Using address: %s\n", address)

	// Build input based on operation
	input := map[string]interface{}{
		"domain": *domain,
	}

	// Add optional callback URL if provided
	if *callbackURL != "" {
		input["callback_url"] = *callbackURL
		fmt.Printf("Callback URL: %s\n", *callbackURL)
	}

	switch strings.ToLower(*operation) {
	case "create":
		if *tholdPrice == "" {
			fmt.Println("Error: --thold-price is required for CREATE operation")
			os.Exit(1)
		}
		// Parse price as float64
		var priceFloat float64
		_, err := fmt.Sscanf(*tholdPrice, "%f", &priceFloat)
		if err != nil {
			fmt.Printf("Error parsing thold-price: %v\n", err)
			os.Exit(1)
		}
		input["thold_price"] = priceFloat
		fmt.Printf("CREATE operation: domain=%s, thold_price=%.2f\n", *domain, priceFloat)
	case "check":
		if *tholdHash == "" {
			fmt.Println("Error: --thold-hash is required for CHECK operation")
			os.Exit(1)
		}
		// Validate thold_hash is exactly 40 hex characters (20 bytes Hash160)
		if len(*tholdHash) != 40 {
			fmt.Printf("Error: --thold-hash must be exactly 40 hex characters, got %d\n", len(*tholdHash))
			os.Exit(1)
		}
		if _, err := hex.DecodeString(*tholdHash); err != nil {
			fmt.Printf("Error: --thold-hash must be valid hex: %v\n", err)
			os.Exit(1)
		}
		input["thold_hash"] = *tholdHash
		fmt.Printf("CHECK operation: domain=%s, thold_hash=%s\n", *domain, *tholdHash)
	default:
		fmt.Printf("Error: invalid operation '%s' (must be 'create' or 'check')\n", *operation)
		os.Exit(1)
	}

	// Create JSON-RPC request
	requestID := uuid.New().String()
	request := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      requestID,
		Method:  "workflows.execute",
		Params: map[string]interface{}{
			"input": input,
			"workflow": map[string]interface{}{
				"workflowID": *workflowID,
			},
		},
	}

	// Marshal request body with sorted keys for digest computation
	requestBody, err := marshalSorted(request)
	if err != nil {
		fmt.Printf("Error marshaling request: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("\nJSON-RPC Request:\n%s\n\n", string(requestBody))

	// Compute digest
	digest := computeDigest(requestBody)
	fmt.Printf("Digest: %s\n", digest)

	// Generate JWT using shared ethsign package
	jwt, err := ethsign.GenerateJWT(privKey, address, digest, uuid.New().String())
	if err != nil {
		fmt.Printf("Error generating JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("JWT: %s\n\n", jwt)

	// Send request to gateway
	fmt.Printf("Sending request to %s\n\n", GatewayURL)

	resp, err := sendRequest(GatewayURL, requestBody, jwt)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Parse and display response
	var jsonResp JSONRPCResponse
	if err := json.Unmarshal(resp, &jsonResp); err != nil {
		fmt.Printf("Error parsing response: %v\n", err)
		fmt.Printf("Raw response: %s\n", string(resp))
		os.Exit(1)
	}

	if jsonResp.Error != nil {
		fmt.Printf("RPC Error [%d]: %s\n", jsonResp.Error.Code, jsonResp.Error.Message)
		os.Exit(1)
	}

	fmt.Printf("Success!\n\n")
	fmt.Printf("Response:\n")
	prettyResp, _ := json.MarshalIndent(jsonResp, "", "  ")
	fmt.Printf("%s\n\n", string(prettyResp))

	// Extract execution ID
	if execID, ok := jsonResp.Result["workflow_execution_id"].(string); ok {
		fmt.Printf("Track execution at: https://cre.chain.link/workflows?execution=%s\n", execID)
	}
}

// marshalSorted marshals v to JSON with all map keys sorted lexicographically at every level.
// It normalizes the input using the standard encoding/json round-trip and then produces a
// deterministic JSON encoding with stable key ordering; it returns the encoded bytes or an error.
func marshalSorted(v interface{}) ([]byte, error) {
	// Convert to map structure first
	temp, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}

	var data interface{}
	if err := json.Unmarshal(temp, &data); err != nil {
		return nil, err
	}

	// Custom marshal with sorted keys
	var buf bytes.Buffer
	if err := marshalSortedRecursive(&buf, data); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// marshalSortedRecursive writes the JSON encoding of v to buf with all map keys
// sorted lexicographically at every level.
//
// It accepts maps of the concrete type map[string]interface{}, slices ([]interface{}),
// and primitive values; nested structures are handled recursively. If encoding any
// value fails, the encountered error is returned.
func marshalSortedRecursive(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case map[string]interface{}:
		buf.WriteString("{")
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		for i, k := range keys {
			if i > 0 {
				buf.WriteString(",")
			}
			keyBytes, _ := json.Marshal(k)
			buf.Write(keyBytes)
			buf.WriteString(":")
			if err := marshalSortedRecursive(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteString("}")
	case []interface{}:
		buf.WriteString("[")
		for i, item := range val {
			if i > 0 {
				buf.WriteString(",")
			}
			if err := marshalSortedRecursive(buf, item); err != nil {
				return err
			}
		}
		buf.WriteString("]")
	default:
		bytes, err := json.Marshal(val)
		if err != nil {
			return err
		}
		buf.Write(bytes)
	}
	return nil
}

// computeDigest returns the SHA-256 digest of the input data as a hex string prefixed with "0x".
func computeDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// sendRequest sends an HTTP POST with the given JSON body and a Bearer JWT in the Authorization header.
// It returns the response body when the server responds with HTTP 200 or 202.
// For any other HTTP status it returns an error containing the status code and the response body.
func sendRequest(url string, body []byte, jwt string) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+jwt)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Accept 200 (OK) and 202 (Accepted) as success
	if resp.StatusCode != 200 && resp.StatusCode != 202 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(respBody))
	}

	return respBody, nil
}
