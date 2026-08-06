//go:build wasip1

// Command cre-tester is a MINIMAL Chainlink Data Streams H1-verification tester.
//
// Its sole purpose is to PROVE the new ducat/datastream H1 verification code
// works against a REAL Chainlink Data Streams report (not a synthetic one),
// runnable via `cre workflow simulate`.
//
// On its single HTTP trigger it:
//  1. Performs the SAME authenticated fetch as hmac-dev/price.go (server-time
//     handshake, HMAC-SHA256 sign, GET /api/v1/reports/latest?feedID=...) to get
//     ONE real fullReport hex.
//  2. Hex-decodes it and runs datastream.DecodeFullReport + DecodeV3Price.
//  3. LOGS (prefixed "H1-TESTER"): the decoded price (scaled /1e18), feedId hex,
//     observationsTimestamp, the number of signatures, and EACH recovered signer
//     address from datastream.RecoverReportSigners — so an operator can compare
//     them against the on-chain Verifier signer set.
//  4. LOGS whether the decoded feedId matches the configured feed_id.
//
// It does NOT require report_signers to be set — the whole point is DISCOVERING
// the real recovered addresses. It fails loudly (returns an error and logs it)
// if the fetch or decode fails.
//
// wasip1-safe: no goroutines, no net/os beyond the CRE http capability.
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

	ducatcrypto "ducat/crypto"
	"ducat/datastream"
	"ducat/shared"

	pb "github.com/smartcontractkit/chainlink-protos/cre/go/sdk"
	"github.com/smartcontractkit/cre-sdk-go/capabilities/networking/http"
	"github.com/smartcontractkit/cre-sdk-go/cre"
	"github.com/smartcontractkit/cre-sdk-go/cre/wasm"
)

// Config is the tester config. We reuse the shared Config struct so the same
// client_id / data_stream_url / feed_id fields work as in hmac/hmac-dev.
type Config = shared.Config

// SecretClientSecret is the CRE vault secret id for the Chainlink Data Streams
// HMAC client secret — identical to hmac-dev/main.go.
const SecretClientSecret = "client_secret"

// logPrefix is the clear, greppable prefix the operator looks for.
const logPrefix = "H1-TESTER"

// TesterResult is returned from the HTTP handler. CRE consensus aggregation
// tags are required for types returned through http.SendRequest /
// ConsensusAggregationFromTags; "identical" is correct because every DON node
// decodes the same report.
type TesterResult struct {
	OK              bool     `json:"ok"                consensus_aggregation:"identical"`
	Price           string   `json:"price"             consensus_aggregation:"identical"`
	FeedID          string   `json:"feed_id"           consensus_aggregation:"identical"`
	FeedIDMatches   bool     `json:"feed_id_matches"   consensus_aggregation:"identical"`
	ObsTimestamp    uint32   `json:"obs_timestamp"     consensus_aggregation:"identical"`
	NumSignatures   int      `json:"num_signatures"    consensus_aggregation:"identical"`
	ConfigDigest    string   `json:"config_digest"     consensus_aggregation:"identical"`
	RecoveredSigner []string `json:"recovered_signers" consensus_aggregation:"identical"`
	VerifyResult    string   `json:"verify_result"     consensus_aggregation:"identical"`
	Message         string   `json:"message"           consensus_aggregation:"identical"`
}

// onHttpTrigger is the single tester handler. The HTTP payload is ignored — any
// trivial input fires the test.
func onHttpTrigger(config *Config, runtime cre.Runtime, _ *http.Payload) (*TesterResult, error) {
	logger := runtime.Logger()
	logger.Info(logPrefix + ": trigger received, starting real Chainlink Data Streams H1 verification test")

	if config == nil {
		return nil, loud(logger, fmt.Errorf("config is nil"))
	}
	logger.Info(logPrefix+": config",
		"client_id", config.ClientID,
		"data_stream_url", config.DataStreamURL,
		"feed_id", config.FeedID,
	)

	// Fetch the Chainlink client_secret from the CRE vault (same id as hmac-dev).
	clientSecretReq := &pb.SecretRequest{Id: SecretClientSecret}
	clientSecret, err := runtime.GetSecret(clientSecretReq).Await()
	if err != nil {
		return nil, loud(logger, fmt.Errorf("failed to fetch client_secret from vault: %w", err))
	}
	if clientSecret.Value == "" {
		return nil, loud(logger, fmt.Errorf("client_secret from vault is empty"))
	}
	clientSecretBytes := []byte(clientSecret.Value)
	if err := ducatcrypto.ValidateClientSecretNotRevoked(clientSecretBytes); err != nil {
		for i := range clientSecretBytes {
			clientSecretBytes[i] = 0
		}
		return nil, loud(logger, fmt.Errorf("client_secret rejected: %w", err))
	}
	for i := range clientSecretBytes {
		clientSecretBytes[i] = 0
	}

	// Run the authenticated fetch + decode inside an http.SendRequest so we have
	// access to the CRE http capability (the *http.SendRequester), under CRE
	// consensus aggregation.
	client := &http.Client{}
	promise := http.SendRequest(config, runtime, client,
		func(cfg *Config, log *slog.Logger, sr *http.SendRequester) (*TesterResult, error) {
			return fetchAndVerify(cfg, clientSecret.Value, log, sr)
		},
		cre.ConsensusAggregationFromTags[*TesterResult](),
	)

	result, err := promise.Await()
	if err != nil {
		return nil, loud(logger, fmt.Errorf("tester fetch/verify failed: %w", err))
	}

	logger.Info(logPrefix+": DONE — real report decoded and signers recovered",
		"price", result.Price,
		"feedId", result.FeedID,
		"feedIdMatches", result.FeedIDMatches,
		"numSignatures", result.NumSignatures,
		"recoveredSigners", strings.Join(result.RecoveredSigner, ","),
	)
	return result, nil
}

// loud logs an error with the H1-TESTER prefix and returns it unchanged, so a
// failure is both surfaced to the caller AND visible in the simulate logs.
func loud(logger *slog.Logger, err error) error {
	logger.Error(logPrefix+": FAILURE", "error", err)
	return err
}

// fetchAndVerify performs ONE authenticated Chainlink Data Streams fetch
// (server-time handshake + HMAC sign + GET) and then decodes + recovers signers
// from the real report. It is a trimmed copy of hmac-dev/price.go's
// fetchPriceOnce + decodeAndVerifyReport, with NO authorization check — it logs
// the recovered signers for discovery instead of verifying them.
func fetchAndVerify(cfg *Config, clientSecret string, logger *slog.Logger, requester *http.SendRequester) (*TesterResult, error) {
	if cfg.FeedID == "" {
		return nil, fmt.Errorf("feed_id cannot be empty")
	}
	if cfg.DataStreamURL == "" {
		return nil, fmt.Errorf("data_stream_url cannot be empty")
	}
	if cfg.ClientID == "" {
		return nil, fmt.Errorf("client_id cannot be empty")
	}

	path := "/api/v1/reports/latest?feedID=" + cfg.FeedID
	url := cfg.DataStreamURL + path

	// 1) Server-time handshake: send an intentionally invalid request and parse
	//    the server's current timestamp out of the error message.
	logger.Info(logPrefix + ": performing server-time handshake")
	testResp, err := requester.SendRequest(&http.Request{
		Url:    url,
		Method: "GET",
		Headers: map[string]string{
			"Authorization":                    cfg.ClientID,
			"X-Authorization-Timestamp":        "1",
			"X-Authorization-Signature-SHA256": "test",
		},
	}).Await()
	if err != nil {
		return nil, fmt.Errorf("server time request failed: %w", err)
	}

	var errorResp map[string]any
	if err := json.Unmarshal(testResp.Body, &errorResp); err != nil {
		return nil, fmt.Errorf("server time parsing failed (status %d, body %q): %w", testResp.StatusCode, string(testResp.Body), err)
	}

	var serverTime int64
	if errMsg, ok := errorResp["error"].(string); ok {
		fmt.Sscanf(errMsg, "invalid X-Authorization-Timestamp header, timestamp is outside of tolerance window: (current: %d", &serverTime)
	}
	if serverTime < 1600000000000 || serverTime > 2000000000000 {
		return nil, fmt.Errorf("server did not return a valid timestamp (got %d); body=%q", serverTime, string(testResp.Body))
	}

	// 2) Sign the request: HMAC-SHA256 over "GET <path> <bodyHash> <clientId> <ts>".
	timestamp := strconv.FormatInt(serverTime+1000, 10)
	bodyHash := hex.EncodeToString(sha256.New().Sum(nil))
	message := fmt.Sprintf("GET %s %s %s %s", path, bodyHash, cfg.ClientID, timestamp)

	h := hmac.New(sha256.New, []byte(clientSecret))
	if _, err := h.Write([]byte(message)); err != nil {
		return nil, fmt.Errorf("authentication signing failed: %w", err)
	}
	signature := hex.EncodeToString(h.Sum(nil))

	// 3) Authenticated GET for the latest report.
	logger.Info(logPrefix + ": fetching latest report")
	resp, err := requester.SendRequest(&http.Request{
		Url:    url,
		Method: "GET",
		Headers: map[string]string{
			"Authorization":                    cfg.ClientID,
			"X-Authorization-Timestamp":        timestamp,
			"X-Authorization-Signature-SHA256": signature,
		},
	}).Await()
	if err != nil {
		return nil, fmt.Errorf("price request failed: %w", err)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("price request failed with status %d: %s", resp.StatusCode, string(resp.Body))
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

	// 4) Decode + recover signers from the REAL report.
	return decodeAndLog(report.Report.FullReport, cfg, logger)
}

// decodeAndLog hex-decodes the fullReport, runs DecodeFullReport + DecodeV3Price,
// recovers ALL signer addresses (no authorization check), and LOGS everything
// with the H1-TESTER prefix so the operator can compare the recovered addresses
// against the on-chain Verifier signer set.
func decodeAndLog(reportHex string, cfg *Config, logger *slog.Logger) (*TesterResult, error) {
	reportBytes, err := hex.DecodeString(strings.TrimPrefix(strings.TrimPrefix(reportHex, "0x"), "0X"))
	if err != nil {
		return nil, fmt.Errorf("hex decode failed: %w", err)
	}
	logger.Info(logPrefix+": decoded fullReport hex", "reportLen", len(reportBytes))

	reportContext, reportBlob, rs, ss, vs, err := datastream.DecodeFullReport(reportBytes)
	if err != nil {
		return nil, fmt.Errorf("DecodeFullReport failed: %w", err)
	}

	feedID, priceInt, obsTs, err := datastream.DecodeV3Price(reportBlob)
	if err != nil {
		return nil, fmt.Errorf("DecodeV3Price failed: %w", err)
	}

	// Scale the raw int192 price by 1e18 to a human price.
	priceFloat := new(big.Float).SetInt(priceInt)
	priceFloat.Quo(priceFloat, big.NewFloat(1e18))
	priceStr := priceFloat.Text('f', 8)

	feedIDHex := "0x" + hex.EncodeToString(feedID[:])
	feedMatches := datastream.FeedIDMatches(feedID, cfg.FeedID)

	// configDigest is reportContext[0]: the on-chain key under which the Verifier
	// stores the authorized signer set for this report. Log it so the operator
	// can read the matching signer config from the Verifier contract.
	configDigestHex := "0x" + hex.EncodeToString(reportContext[0][:])

	logger.Info(logPrefix+": decoded v3 report",
		"price", priceStr,
		"priceRawInt192", priceInt.String(),
		"feedId", feedIDHex,
		"configuredFeedId", cfg.FeedID,
		"feedIdMatches", feedMatches,
		"observationsTimestamp", obsTs,
		"numSignatures", len(rs),
		"configDigest", configDigestHex,
	)
	if !feedMatches {
		return nil, fmt.Errorf("decoded feedId %s does not match configured feed_id %s", feedIDHex, cfg.FeedID)
	}

	// Recover ALL signer addresses as untrusted discovery candidates. Recovery
	// proves only control of the signing keys for this report; operators must
	// still bind the full configDigest/signer/f tuple to the on-chain Verifier.
	signers, err := datastream.RecoverReportSigners(reportContext, reportBlob, rs, ss, vs)
	if err != nil {
		return nil, fmt.Errorf("RecoverReportSigners failed: %w", err)
	}

	signerHexes := make([]string, 0, len(signers))
	for i, addr := range signers {
		addrHex := "0x" + hex.EncodeToString(addr[:])
		signerHexes = append(signerHexes, addrHex)
		logger.Info(logPrefix+": recovered candidate signer (untrusted until on-chain confirmation)",
			"index", i, "address", addrHex)
	}

	// If report_signers is configured, exercise the REAL enforcement path
	// (datastream.VerifyReportSigners) against this live report — this proves the
	// fail-closed verification actually accepts a genuine report.
	verifyResult := "discovery only (no report_signers configured; candidates are untrusted)"
	if len(cfg.ReportSigners) > 0 {
		authorized, err := datastream.BuildAuthorizedSignerSet(cfg.ReportSigners)
		if err != nil {
			return nil, fmt.Errorf("invalid report_signers config: %w", err)
		}
		threshold := cfg.EffectiveReportSignerThreshold()
		if err := datastream.VerifyReportSigners(reportContext, reportBlob, rs, ss, vs, authorized, threshold); err != nil {
			logger.Error(logPrefix+": VERIFICATION FAILED on a real report",
				"error", err, "threshold", threshold, "authorizedSigners", len(authorized))
			return nil, fmt.Errorf("configured signer verification failed: %w", err)
		}
		verifyResult = fmt.Sprintf("PASSED (threshold %d, %d authorized signers; configDigest still requires on-chain confirmation)", threshold, len(authorized))
		logger.Info(logPrefix+": SIGNER VERIFICATION PASSED; configDigest still requires on-chain confirmation",
			"threshold", threshold, "authorizedSigners", len(authorized))
	}

	return &TesterResult{
		OK:              true,
		Price:           priceStr,
		FeedID:          feedIDHex,
		FeedIDMatches:   feedMatches,
		ObsTimestamp:    obsTs,
		NumSignatures:   len(rs),
		ConfigDigest:    configDigestHex,
		RecoveredSigner: signerHexes,
		VerifyResult:    verifyResult,
		Message:         fmt.Sprintf("decoded real Chainlink report and recovered %d signer(s); verification: %s", len(signers), verifyResult),
	}, nil
}

// InitWorkflow registers the single HTTP trigger handler.
func InitWorkflow(config *Config, logger *slog.Logger, _ cre.SecretsProvider) (cre.Workflow[*Config], error) {
	// Minimal validation: only the fields the tester needs. We intentionally do
	// NOT call config.Validate() (which requires relay_url / authorized_key /
	// network etc.) because the tester config is deliberately minimal.
	if config.ClientID == "" {
		return cre.Workflow[*Config]{}, fmt.Errorf("client_id required")
	}
	if config.DataStreamURL == "" {
		return cre.Workflow[*Config]{}, fmt.Errorf("data_stream_url required")
	}
	if config.FeedID == "" {
		return cre.Workflow[*Config]{}, fmt.Errorf("feed_id required")
	}
	if config.AuthorizedKey == "" {
		return cre.Workflow[*Config]{}, fmt.Errorf("authorized_key required for HTTP trigger auth")
	}

	logger.Info(logPrefix+": workflow initialized",
		"data_stream_url", config.DataStreamURL,
		"feed_id", config.FeedID,
	)

	httpConfig := &http.Config{
		AuthorizedKeys: []*http.AuthorizedKey{
			{
				Type:      http.KeyType_KEY_TYPE_ECDSA_EVM,
				PublicKey: config.AuthorizedKey,
			},
		},
	}

	return cre.Workflow[*Config]{
		cre.Handler(http.Trigger(httpConfig), onHttpTrigger),
	}, nil
}

func main() {
	wasm.NewRunner(cre.ParseJSON[Config]).Run(InitWorkflow)
}
