//go:build wasip1

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"

	"github.com/shopspring/decimal"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
)

// Chainlink Data Streams price fetching with HMAC-SHA256 auth

// fetchPrice fetches BTC/USD price from Chainlink Data Streams
func fetchPrice(wc *WorkflowConfig, logger *slog.Logger, requester *http.SendRequester) (*PriceData, error) {
	// Validate configuration
	if wc == nil || wc.Config == nil {
		return nil, fmt.Errorf("config cannot be nil")
	}
	if wc.Config.FeedID == "" {
		return nil, fmt.Errorf("feed ID cannot be empty")
	}
	if wc.Config.DataStreamURL == "" {
		return nil, fmt.Errorf("data stream URL cannot be empty")
	}
	if wc.Config.ClientID == "" {
		return nil, fmt.Errorf("client ID cannot be empty")
	}
	if wc.ClientSecret == "" {
		return nil, fmt.Errorf("client secret cannot be empty")
	}

	// Construct API endpoint
	path := "/api/v1/reports/latest?feedID=" + wc.Config.FeedID
	url := wc.Config.DataStreamURL + path

	// Get server time using intentionally invalid request
	// Server responds with error message containing current timestamp
	// This is required because CRE runtime has limited time access
	testResp, err := requester.SendRequest(&http.Request{
		Url:    url,
		Method: "GET",
		Headers: map[string]string{
			"Authorization":                    wc.Config.ClientID,
			"X-Authorization-Timestamp":        "1", // Invalid timestamp triggers error response
			"X-Authorization-Signature-SHA256": "test",
		},
	}).Await()
	if err != nil {
		return nil, fmt.Errorf("server time request failed: %w", err)
	}

	// Parse error response to extract server timestamp
	var errorResp map[string]interface{}
	if err := json.Unmarshal(testResp.Body, &errorResp); err != nil {
		return nil, fmt.Errorf("server time parsing failed: %w", err)
	}

	// Extract timestamp from error message
	// Format: "invalid X-Authorization-Timestamp header, timestamp is outside of tolerance window: (current: 1234567890)"
	var serverTime int64
	if errMsg, ok := errorResp["error"].(string); ok {
		fmt.Sscanf(errMsg, "invalid X-Authorization-Timestamp header, timestamp is outside of tolerance window: (current: %d", &serverTime)
	}

	// Validate extracted timestamp is reasonable (between Sept 2020 and Sept 2033)
	// Fail if invalid - we need consistent timestamps across all DON nodes for consensus
	if serverTime < 1600000000000 || serverTime > 2000000000000 {
		return nil, fmt.Errorf("server did not return valid timestamp (got %d), cannot proceed without consensus-safe time", serverTime)
	}

	// Construct authenticated request
	// Add 1 second buffer to ensure timestamp is within server's tolerance window
	timestamp := strconv.FormatInt(serverTime+1000, 10)

	// Compute empty body hash (GET request has no body)
	bodyHash := hex.EncodeToString(sha256.New().Sum(nil))

	// Construct authentication message
	// Format: METHOD path bodyHash clientID timestamp
	message := fmt.Sprintf("GET %s %s %s %s", path, bodyHash, wc.Config.ClientID, timestamp)

	// Sign message with HMAC-SHA256 using client secret (from secrets)
	h := hmac.New(sha256.New, []byte(wc.ClientSecret))
	if _, err := h.Write([]byte(message)); err != nil {
		return nil, fmt.Errorf("authentication signing failed: %w", err)
	}
	signature := hex.EncodeToString(h.Sum(nil))

	// Send authenticated price request
	resp, err := requester.SendRequest(&http.Request{
		Url:    url,
		Method: "GET",
		Headers: map[string]string{
			"Authorization":                    wc.Config.ClientID,
			"X-Authorization-Timestamp":        timestamp,
			"X-Authorization-Signature-SHA256": signature,
		},
	}).Await()
	if err != nil {
		return nil, fmt.Errorf("price request failed: %w", err)
	}

	// Validate response status
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("price request failed with status %d: %s", resp.StatusCode, string(resp.Body))
	}

	// Parse price report response
	var report struct {
		Report struct {
			ObservationsTimestamp int64  `json:"observationsTimestamp"` // DON consensus timestamp
			FullReport            string `json:"fullReport"`            // Hex-encoded Merkle root report
		} `json:"report"`
	}
	if err := json.Unmarshal(resp.Body, &report); err != nil {
		return nil, fmt.Errorf("report parsing failed: %w", err)
	}

	// Validate report is not empty
	if report.Report.FullReport == "" {
		return nil, fmt.Errorf("empty report received from Chainlink")
	}

	// Decode price from hex-encoded report
	price, err := decodePrice(report.Report.FullReport)
	if err != nil {
		return nil, fmt.Errorf("price decode failed: %w", err)
	}

	// Validate decoded price is within reasonable bounds
	if err := validatePriceForEncoding(price); err != nil {
		return nil, fmt.Errorf("invalid price received: %w", err)
	}

	// Convert milliseconds to seconds for consistency with Unix timestamps
	priceStamp := serverTime / 1000
	logger.Info("Price fetched successfully", "price", price, "stamp", priceStamp)

	return &PriceData{
		Price:  decimal.NewFromFloat(price),
		Origin: OriginChainlinkDataStream,
		Stamp:  priceStamp,
	}, nil
}

// decodePrice extracts BTC/USD from Chainlink report
// Tries multiple offsets, returns first valid price (18 decimals)
func decodePrice(reportHex string) (float64, error) {
	// Validate input
	if reportHex == "" {
		return 0, fmt.Errorf("report hex cannot be empty")
	}

	// Decode hex to bytes (handle optional 0x prefix)
	reportBytes, err := hex.DecodeString(strings.TrimPrefix(reportHex, "0x"))
	if err != nil {
		return 0, fmt.Errorf("hex decode failed: %w", err)
	}

	// Validate minimum report length
	// Report contains multiple 32-byte fields, minimum 544 bytes total
	if len(reportBytes) < 544 {
		return 0, fmt.Errorf("report too short: expected at least 544 bytes, got %d", len(reportBytes))
	}

	// Try multiple known price field offsets in Chainlink report structure
	// Different feed versions may store price at different offsets
	offsets := []int{448, 480, 512}
	var validPrices []float64

	for _, offset := range offsets {
		// Safety check for buffer overflow
		if offset+32 > len(reportBytes) {
			continue
		}

		// Extract 32-byte price field as big integer
		priceInt := new(big.Int).SetBytes(reportBytes[offset : offset+32])

		// Skip if price is zero or negative
		if priceInt.Sign() <= 0 {
			continue
		}

		// Convert from wei-like format (18 decimals) to float64
		priceBig := new(big.Float).SetInt(priceInt)
		priceBig.Quo(priceBig, big.NewFloat(1e18))
		price, _ := priceBig.Float64()

		// Validate price is within reasonable bounds for BTC/USD
		if price >= MinReasonablePrice && price <= MaxReasonablePrice {
			validPrices = append(validPrices, price)
		}
	}

	// Ensure at least one valid price was found
	if len(validPrices) == 0 {
		return 0, fmt.Errorf("no valid price found in report at offsets %v", offsets)
	}

	// Return first valid price found
	return validPrices[0], nil
}

// validatePriceForEncoding validates price bounds
func validatePriceForEncoding(price float64) error {
	// Check lower bound
	if price < MinReasonablePrice {
		return fmt.Errorf("price %.2f below minimum %.2f", price, MinReasonablePrice)
	}

	// Check upper bound
	if price > MaxReasonablePrice {
		return fmt.Errorf("price %.2f exceeds maximum %.2f", price, MaxReasonablePrice)
	}

	return nil
}
