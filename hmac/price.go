//go:build wasip1

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strconv"
	"strings"

	"ducat/datastream"

	"github.com/shopspring/decimal"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
)

// Chainlink Data Streams price fetching with HMAC-SHA256 auth

// fetchPriceMaxAttempts caps how many times each DON node will retry the
// Chainlink fetch before reporting failure to consensus. The retry happens
// per-node so a single transient timeout doesn't fail the whole DON round.
// 3 attempts x 2 HTTP calls each = 6 HTTP calls worst case per node, under
// CRE's 10-call budget for create/evaluate paths.
const fetchPriceMaxAttempts = 3

type nonRetryablePriceError struct {
	err error
}

func (e *nonRetryablePriceError) Error() string {
	return e.err.Error()
}

func (e *nonRetryablePriceError) Unwrap() error {
	return e.err
}

func isNonRetryablePriceError(err error) bool {
	var nonRetryable *nonRetryablePriceError
	return errors.As(err, &nonRetryable)
}

// fetchPrice wraps fetchPriceOnce in a per-node retry loop. CRE's consensus
// aggregation runs after this returns, so retries are local to each DON node.
// Transient Chainlink/Data Streams gateway failures should not fail the whole
// DON round; entitlement/feed errors should fail fast.
func fetchPrice(wc *WorkflowConfig, logger *slog.Logger, requester *http.SendRequester) (*PriceData, error) {
	var lastErr error
	for attempt := 1; attempt <= fetchPriceMaxAttempts; attempt++ {
		data, err := fetchPriceOnce(wc, logger, requester)
		if err == nil {
			if attempt > 1 {
				logger.Info("Chainlink fetch succeeded after retry", "attempt", attempt)
			}
			return data, nil
		}
		lastErr = err
		logger.Warn("Chainlink fetch attempt failed", "attempt", attempt, "error", err)
		if isNonRetryablePriceError(err) {
			return nil, err
		}
	}
	return nil, fmt.Errorf("Chainlink fetch failed after %d attempts: %w", fetchPriceMaxAttempts, lastErr)
}

// fetchPriceOnce performs a single Chainlink Data Streams fetch.
func fetchPriceOnce(wc *WorkflowConfig, logger *slog.Logger, requester *http.SendRequester) (*PriceData, error) {
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
		err := fmt.Errorf("price request failed with status %d: %s", resp.StatusCode, string(resp.Body))
		if resp.StatusCode == 401 || resp.StatusCode == 403 ||
			(resp.StatusCode == 404 && strings.Contains(string(resp.Body), "report not found")) {
			return nil, &nonRetryablePriceError{err: err}
		}
		return nil, err
	}

	// Parse price report response
	var report struct {
		Report struct {
			FullReport string `json:"fullReport"` // Hex-encoded signed report
		} `json:"report"`
	}
	if err := json.Unmarshal(resp.Body, &report); err != nil {
		return nil, fmt.Errorf("report parsing failed: %w", err)
	}

	// Validate report is not empty
	if report.Report.FullReport == "" {
		return nil, fmt.Errorf("empty report received from Chainlink")
	}

	// SECURITY (H1): Decode + cryptographically verify the Chainlink report.
	//
	// This replaces the old brute-force offset scan (which accepted the first
	// value that "looked like" a price WITHOUT verifying DON signatures) with:
	//   1. A proper Solidity-ABI decode of the fullReport envelope.
	//   2. A proper v3 decode reading the price as a SIGNED int192 at offset 192.
	//   3. DON signature verification (gated by RequireReportVerification).
	price, observationsTimestamp, err := decodeAndVerifyReport(report.Report.FullReport, wc.Config, logger)
	if err != nil {
		return nil, fmt.Errorf("price decode/verify failed: %w", err)
	}

	// Validate decoded price is within reasonable bounds
	if err := validatePriceForEncoding(price); err != nil {
		return nil, fmt.Errorf("invalid price received: %w", err)
	}

	// The event timestamp is the observation timestamp embedded in the signed
	// report blob, not mutable metadata in the outer HTTP JSON response.
	priceStamp := observationsTimestamp

	// SECURITY: Validate timestamp precision and bounds after conversion
	// Ensures the Unix timestamp is within reasonable range (2000-2100)
	// and hasn't been truncated incorrectly from milliseconds
	if priceStamp < 946684800 { // 2000-01-01
		return nil, fmt.Errorf("price timestamp too old: %d (before year 2000)", priceStamp)
	}
	if priceStamp > 4102444800 { // 2100-01-01
		return nil, fmt.Errorf("price timestamp too far in future: %d (after year 2100)", priceStamp)
	}

	// SECURITY (H3): staleness check against the report's SIGNED observations
	// timestamp. The DON signs observationsTimestamp, so it is the trustworthy
	// clock; reject (do not merely warn) when the signed timestamp is too far
	// from server time, and require it to be present — a report we cannot
	// staleness-check (or one that is stale/replayed) must not drive liquidations.
	if observationsTimestamp <= 0 {
		return nil, fmt.Errorf("report missing observations timestamp; cannot verify price freshness")
	}
	// Compare the signed report timestamp with the Data Engine's server time.
	serverTimeSec := serverTime / 1000
	timeDiff := serverTimeSec - observationsTimestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > MaxPriceStalenessSec {
		return nil, fmt.Errorf("price report is stale: signed observation time %d differs from server time %d by %ds (max %ds)",
			observationsTimestamp, serverTimeSec, timeDiff, MaxPriceStalenessSec)
	}

	logger.Info("Price fetched successfully", "price", price, "stamp", priceStamp)

	return &PriceData{
		Price:  decimal.NewFromFloat(price),
		Origin: OriginChainlinkDataStream,
		Stamp:  priceStamp,
	}, nil
}

// decodeAndVerifyReport decodes the Chainlink Data Streams fullReport, reads the
// price as a SIGNED int192 at the correct offset 192, returns the SIGNED
// observations timestamp from that blob, and (when configured) cryptographically
// verifies the DON signatures.
//
// SECURITY (H1): This is money-path code and FAILS CLOSED. The price is returned
// only if:
//   - the outer ABI envelope decodes,
//   - the v3 reportBlob decodes and the price word is well-formed,
//   - the decoded feedId matches cfg.FeedID,
//   - AND, when cfg.RequireReportVerification is true, at least
//     EffectiveReportSignerThreshold() distinct DON signers (all in
//     cfg.ReportSigners) signed the report.
//
// Config validation permits cfg.RequireReportVerification=false only with a
// loopback Data Streams endpoint. That development mode logs a warning on every
// fetch.
func decodeAndVerifyReport(reportHex string, cfg *Config, logger *slog.Logger) (float64, int64, error) {
	if reportHex == "" {
		return 0, 0, fmt.Errorf("report hex cannot be empty")
	}

	reportBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(reportHex, "0x"), "0X"))
	if err != nil {
		return 0, 0, fmt.Errorf("hex decode failed: %w", err)
	}

	// 1. Decode the outer Solidity-ABI fullReport envelope.
	reportContext, reportBlob, rs, ss, vs, err := datastream.DecodeFullReport(reportBytes)
	if err != nil {
		return 0, 0, fmt.Errorf("fullReport decode failed: %w", err)
	}

	// 2. Decode the v3 reportBlob: feedId + signed int192 price at offset 192.
	feedID, priceInt, signedObservationsTimestamp, err := datastream.DecodeV3Price(reportBlob)
	if err != nil {
		return 0, 0, fmt.Errorf("v3 report decode failed: %w", err)
	}

	// 3. The decoded feedId MUST match the configured feed (fail closed).
	if !datastream.FeedIDMatches(feedID, cfg.FeedID) {
		return 0, 0, fmt.Errorf("report feedId 0x%x does not match configured feed_id %s", feedID, cfg.FeedID)
	}

	// Price must be positive (BTC/USD never negative for our use).
	if priceInt.Sign() <= 0 {
		return 0, 0, fmt.Errorf("decoded price is non-positive: %s", priceInt.String())
	}

	// 4. DON signature verification, gated for rollout.
	if cfg.RequireReportVerification {
		authorized, err := datastream.BuildAuthorizedSignerSet(cfg.ReportSigners)
		if err != nil {
			return 0, 0, fmt.Errorf("invalid report_signers config: %w", err)
		}
		threshold := cfg.EffectiveReportSignerThreshold()
		if err := datastream.VerifyReportSigners(reportContext, reportBlob, rs, ss, vs, authorized, threshold); err != nil {
			// Fail closed: reject the price entirely.
			return 0, 0, fmt.Errorf("DON signature verification failed: %w", err)
		}
		logger.Debug("Chainlink report DON signatures verified",
			"signatures", len(rs),
			"threshold", threshold,
			"authorizedSigners", len(authorized),
		)
	} else {
		// LOUD warning every fetch: verification is disabled. This is the
		// rollout escape hatch — operators must populate report_signers and
		// flip require_report_verification to true.
		logger.Warn("SECURITY: Chainlink report signature verification is DISABLED (require_report_verification=false). Price is decoded at the correct offset but NOT cryptographically verified against the DON signer set. Populate report_signers and enable verification.",
			"signatures", len(rs),
			"feedID", fmt.Sprintf("0x%x", feedID),
		)
	}

	// Convert from 18-decimal on-chain integer to float64.
	priceBig := new(big.Float).SetInt(priceInt)
	priceBig.Quo(priceBig, big.NewFloat(1e18))
	price, _ := priceBig.Float64()

	logger.Debug("Price decoded from v3 report at offset 192",
		"price", price,
		"reportLen", len(reportBytes),
		"verified", cfg.RequireReportVerification,
	)

	return price, int64(signedObservationsTimestamp), nil
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
