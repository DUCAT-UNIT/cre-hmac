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

// fetchPriceMaxAttempts caps how many times the enclave will retry the
// Chainlink fetch before reporting failure. One attempt is one signed
// Chainlink request, sent exactly once from the TEE (not once per DON node).
// Older builds first sent an intentionally invalid request to scrape Chainlink
// server time, but that extra gateway call was the dominant timeout source.
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

// fetchPrice wraps fetchPriceOnce in a retry loop that runs entirely inside
// the enclave — each attempt is one real outbound HTTP call (counted by the
// teeSender). Drift caused by Chainlink hiccups (Cloudflare 502,
// connection-reset) is the dominant failure mode in dev; one quick retry
// recovers ~all of them.
func fetchPrice(wc *WorkflowConfig, logger *slog.Logger, requester httpSender) (*PriceData, error) {
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
		// No sleep — CRE WASM time.Sleep behavior is finicky and the
		// dominant failure mode is connection timeout, which already
		// burns wall-clock time. Back-to-back retries are appropriate.
	}
	return nil, fmt.Errorf("Chainlink fetch failed after %d attempts: %w", fetchPriceMaxAttempts, lastErr)
}

// fetchPriceOnce performs a single Chainlink Data Streams fetch. Caller wraps
// this in retry.
func fetchPriceOnce(wc *WorkflowConfig, logger *slog.Logger, requester httpSender) (*PriceData, error) {
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

	path := "/api/v1/reports/latest?feedID=" + wc.Config.FeedID
	url := wc.Config.DataStreamURL + path

	// Use the SDK runtime clock (env.now host import), not stdlib time.Now():
	// inside a production enclave the WASI guest clock is not SDK-guaranteed,
	// and a skewed timestamp here fails the Chainlink HMAC tolerance window.
	requestTimeMs := requester.Now().UnixMilli()
	timestamp := strconv.FormatInt(requestTimeMs, 10)
	bodyHash := hex.EncodeToString(sha256.New().Sum(nil))
	message := fmt.Sprintf("GET %s %s %s %s", path, bodyHash, wc.Config.ClientID, timestamp)

	h := hmac.New(sha256.New, []byte(wc.ClientSecret))
	if _, err := h.Write([]byte(message)); err != nil {
		return nil, fmt.Errorf("authentication signing failed: %w", err)
	}
	signature := hex.EncodeToString(h.Sum(nil))

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

	if resp.StatusCode != 200 {
		err := fmt.Errorf("price request failed with status %d: %s", resp.StatusCode, string(resp.Body))
		if resp.StatusCode == 401 || resp.StatusCode == 403 ||
			(resp.StatusCode == 404 && strings.Contains(string(resp.Body), "report not found")) {
			return nil, &nonRetryablePriceError{err: err}
		}
		return nil, err
	}

	var report struct {
		Report struct {
			ObservationsTimestamp int64  `json:"observationsTimestamp"`
			FullReport            string `json:"fullReport"`
		} `json:"report"`
	}
	if err := json.Unmarshal(resp.Body, &report); err != nil {
		return nil, fmt.Errorf("report parsing failed: %w", err)
	}

	if report.Report.FullReport == "" {
		return nil, fmt.Errorf("empty report received from Chainlink")
	}

	// SECURITY (H1): Decode + cryptographically verify the Chainlink report.
	// Replaces the old brute-force offset scan; reads the SIGNED int192 price at
	// offset 192 and (when configured) verifies the DON signatures fail-closed.
	price, err := decodeAndVerifyReport(report.Report.FullReport, wc.Config, logger)
	if err != nil {
		return nil, fmt.Errorf("price decode/verify failed: %w", err)
	}

	if err := validatePriceForEncoding(price); err != nil {
		return nil, fmt.Errorf("invalid price received: %w", err)
	}

	observationsTimestamp := report.Report.ObservationsTimestamp
	priceStamp := observationsTimestamp

	if priceStamp < 946684800 {
		return nil, fmt.Errorf("price timestamp too old: %d (before year 2000)", priceStamp)
	}
	if priceStamp > 4102444800 {
		return nil, fmt.Errorf("price timestamp too far in future: %d (after year 2100)", priceStamp)
	}

	// SECURITY (H3): staleness check against the report's SIGNED observations
	// timestamp. The DON signs observationsTimestamp, so it is the trustworthy
	// clock; reject (do not merely warn) when the signed timestamp is too far
	// from the runtime clock, and require it to be present — a report we cannot
	// staleness-check (or one that is stale/replayed) must not drive
	// liquidations. The reference clock is the SDK runtime clock; a 200 from
	// Chainlink additionally proves that clock sat within the (much tighter)
	// HMAC auth tolerance of server time when the request was signed.
	if observationsTimestamp <= 0 {
		return nil, fmt.Errorf("report missing observations timestamp; cannot verify price freshness")
	}
	timeDiff := requestTimeMs/1000 - observationsTimestamp
	if timeDiff < 0 {
		timeDiff = -timeDiff
	}
	if timeDiff > MaxPriceStalenessSec {
		return nil, fmt.Errorf("price report is stale: signed observation time %d differs from local request time %d by %ds (max %ds)",
			observationsTimestamp, requestTimeMs/1000, timeDiff, MaxPriceStalenessSec)
	}

	logger.Info("Price fetched successfully", "price", price, "stamp", priceStamp)

	return &PriceData{
		Price:  decimal.NewFromFloat(price),
		Origin: OriginChainlinkDataStream,
		Stamp:  priceStamp,
	}, nil
}

// decodeAndVerifyReport decodes the Chainlink Data Streams fullReport, reads the
// price as a SIGNED int192 at the correct offset 192, and (when configured)
// cryptographically verifies the DON signatures.
//
// SECURITY (H1): Money-path code that FAILS CLOSED. The price is returned only
// if the ABI envelope decodes, the v3 blob decodes, the decoded feedId matches
// cfg.FeedID, and — when cfg.RequireReportVerification is true — at least
// EffectiveReportSignerThreshold() distinct DON signers (all in
// cfg.ReportSigners) signed the report. When verification is disabled, a LOUD
// warning is logged each fetch and the correctly-decoded price is still returned
// (rollout escape hatch only).
func decodeAndVerifyReport(reportHex string, cfg *Config, logger *slog.Logger) (float64, error) {
	if reportHex == "" {
		return 0, fmt.Errorf("report hex cannot be empty")
	}

	reportBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(reportHex, "0x"), "0X"))
	if err != nil {
		return 0, fmt.Errorf("hex decode failed: %w", err)
	}

	reportContext, reportBlob, rs, ss, vs, err := datastream.DecodeFullReport(reportBytes)
	if err != nil {
		return 0, fmt.Errorf("fullReport decode failed: %w", err)
	}

	feedID, priceInt, _, err := datastream.DecodeV3Price(reportBlob)
	if err != nil {
		return 0, fmt.Errorf("v3 report decode failed: %w", err)
	}

	if !datastream.FeedIDMatches(feedID, cfg.FeedID) {
		return 0, fmt.Errorf("report feedId 0x%x does not match configured feed_id %s", feedID, cfg.FeedID)
	}

	if priceInt.Sign() <= 0 {
		return 0, fmt.Errorf("decoded price is non-positive: %s", priceInt.String())
	}

	if cfg.RequireReportVerification {
		authorized, err := datastream.BuildAuthorizedSignerSet(cfg.ReportSigners)
		if err != nil {
			return 0, fmt.Errorf("invalid report_signers config: %w", err)
		}
		threshold := cfg.EffectiveReportSignerThreshold()
		if err := datastream.VerifyReportSigners(reportContext, reportBlob, rs, ss, vs, authorized, threshold); err != nil {
			return 0, fmt.Errorf("DON signature verification failed: %w", err)
		}
		logger.Debug("Chainlink report DON signatures verified",
			"signatures", len(rs),
			"threshold", threshold,
			"authorizedSigners", len(authorized),
		)
	} else {
		logger.Warn("SECURITY: Chainlink report signature verification is DISABLED (require_report_verification=false). Price is decoded at the correct offset but NOT cryptographically verified against the DON signer set. Populate report_signers and enable verification.",
			"signatures", len(rs),
			"feedID", fmt.Sprintf("0x%x", feedID),
		)
	}

	priceBig := new(big.Float).SetInt(priceInt)
	priceBig.Quo(priceBig, big.NewFloat(1e18))
	price, _ := priceBig.Float64()

	logger.Debug("Price decoded from v3 report at offset 192",
		"price", price,
		"reportLen", len(reportBytes),
		"verified", cfg.RequireReportVerification,
	)

	return price, nil
}

// validatePriceForEncoding validates price bounds
func validatePriceForEncoding(price float64) error {
	if price < MinReasonablePrice {
		return fmt.Errorf("price %.2f below minimum %.2f", price, MinReasonablePrice)
	}
	if price > MaxReasonablePrice {
		return fmt.Errorf("price %.2f exceeds maximum %.2f", price, MaxReasonablePrice)
	}
	return nil
}
