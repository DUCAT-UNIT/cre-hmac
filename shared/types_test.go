package shared

import (
	"encoding/json"
	"math"
	"strings"
	"testing"
)

// =============================================================================
// Config Validation Tests
// =============================================================================

func TestConfigValidate(t *testing.T) {
	// Valid Ethereum address for testing (42 chars: 0x + 40 hex)
	validAuthKey := "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82"

	validConfig := Config{
		ClientID:      "test-client",
		DataStreamURL: "https://data.example.com",
		FeedID:        "feed-123",
		RelayURL:      "wss://relay.example.com",
		Network:       "mutiny",
		AuthorizedKey: validAuthKey,
	}

	tests := []struct {
		name    string
		config  *Config
		wantErr bool
		errMsg  string
	}{
		{"valid config", &validConfig, false, ""},
		{"nil config", nil, true, "config is nil"},
		{"missing client_id", &Config{DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: validAuthKey}, true, "client_id required"},
		{"missing data_stream_url", &Config{ClientID: "id", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: validAuthKey}, true, "data_stream_url required"},
		{"missing relay_url", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", Network: "net", AuthorizedKey: validAuthKey}, true, "relay_url required"},
		{"missing feed_id", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: validAuthKey}, true, "feed_id required"},
		{"missing network", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", AuthorizedKey: validAuthKey}, true, "network required"},
		// TLS validation
		{"data_stream_url no TLS", &Config{ClientID: "id", DataStreamURL: "http://external.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: validAuthKey}, true, "must use https://"},
		{"data_stream_url localhost allowed", &Config{ClientID: "id", DataStreamURL: "http://localhost:8080", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: validAuthKey}, false, ""},
		{"relay_url no TLS", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "ws://external.example.com", Network: "net", AuthorizedKey: validAuthKey}, true, "must use TLS"},
		{"relay_url localhost allowed", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "ws://localhost:7000", Network: "net", AuthorizedKey: validAuthKey}, false, ""},
		// AuthorizedKey validation
		{"missing authorized_key", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net"}, true, "authorized_key required"},
		{"authorized_key too short", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: "0x123"}, true, "must be 42 characters"},
		{"authorized_key too long", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82a"}, true, "must be 42 characters"},
		{"authorized_key missing 0x", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: "5b3ebc3622dd75f0a680c2b7e4613ad813c72f8200"}, true, "must start with '0x'"},
		{"authorized_key invalid hex", &Config{ClientID: "id", DataStreamURL: "https://data.example.com", FeedID: "feed", RelayURL: "wss://relay.example.com", Network: "net", AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72fGG"}, true, "invalid hex character"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.config == nil {
				err = (*Config)(nil).Validate()
			} else {
				err = tt.config.Validate()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Config.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestConfigValidateCronConfig(t *testing.T) {
	baseConfig := Config{
		ClientID:      "test-client",
		DataStreamURL: "https://data.example.com",
		FeedID:        "feed-123",
		RelayURL:      "wss://relay.example.com",
		Network:       "mutiny",
		AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82",
	}

	tests := []struct {
		name         string
		cronSchedule string
		rateMin      float64
		rateMax      float64
		stepSize     float64
		wantErr      bool
		errMsg       string
	}{
		{"valid cron config", "0 */5 * * * *", 1.35, 5.0, 0.05, false, ""},
		{"no cron config", "", 0, 0, 0, false, ""},
		{"missing cron with rates", "", 1.35, 5.0, 0.05, true, "cron_schedule required"},
		{"cron missing rate_min", "0 */5 * * * *", 0, 5.0, 0.05, true, "rate_min must be positive"},
		{"cron missing rate_max", "0 */5 * * * *", 1.35, 0, 0.05, true, "rate_max must be positive"},
		{"cron missing step_size", "0 */5 * * * *", 1.35, 5.0, 0, true, "step_size must be positive"},
		{"rate_min >= rate_max", "0 */5 * * * *", 5.0, 5.0, 0.05, true, "rate_min (5.0000) must be less than rate_max"},
		{"rate_min too low", "0 */5 * * * *", 1.0, 5.0, 0.05, true, "rate_min must be at least 1.01"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := baseConfig
			config.CronSchedule = tt.cronSchedule
			config.RateMin = tt.rateMin
			config.RateMax = tt.rateMax
			config.StepSize = tt.stepSize

			err := config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("Config.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestConfigJSON(t *testing.T) {
	config := Config{
		ClientID:      "test-client",
		DataStreamURL: "https://data.example.com",
		FeedID:        "feed-123",
		RelayURL:      "wss://relay.example.com",
		Network:       "mutiny",
		AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82",
		CronSchedule:  "0 */5 * * * *",
		RateMin:       1.35,
		RateMax:       5.0,
		StepSize:      0.05,
		QuoteDomain:   "auto-gen",
	}

	jsonData, err := json.Marshal(config)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	var decoded Config
	if err := json.Unmarshal(jsonData, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	if decoded.ClientID != config.ClientID {
		t.Errorf("ClientID = %s, want %s", decoded.ClientID, config.ClientID)
	}
	if decoded.CronSchedule != config.CronSchedule {
		t.Errorf("CronSchedule = %s, want %s", decoded.CronSchedule, config.CronSchedule)
	}
	if decoded.RateMin != config.RateMin {
		t.Errorf("RateMin = %f, want %f", decoded.RateMin, config.RateMin)
	}
}

// =============================================================================
// HttpRequestData Validation Tests
// =============================================================================

func TestHttpRequestDataValidate(t *testing.T) {
	validPrice := 100000.0
	validHash := strings.Repeat("a", 40)

	tests := []struct {
		name    string
		request *HttpRequestData
		wantErr bool
		errMsg  string
	}{
		// Valid requests
		{"valid create request", &HttpRequestData{Domain: "test", TholdPrice: &validPrice}, false, ""},
		{"valid check request", &HttpRequestData{Domain: "test", TholdHash: &validHash}, false, ""},

		// Nil/empty
		{"nil request", nil, true, "request is nil"},

		// Domain validation
		{"empty domain", &HttpRequestData{Domain: "", TholdPrice: &validPrice}, true, "domain required"},
		{"domain too long", &HttpRequestData{Domain: strings.Repeat("a", MaxDomainLength+1), TholdPrice: &validPrice}, true, "domain too long"},
		{"invalid domain chars", &HttpRequestData{Domain: "test@domain", TholdPrice: &validPrice}, true, "invalid characters"},

		// Request type validation
		{"neither price nor hash", &HttpRequestData{Domain: "test"}, true, "either thold_price or thold_hash required"},
		{"both price and hash", &HttpRequestData{Domain: "test", TholdPrice: &validPrice, TholdHash: &validHash}, true, "cannot specify both"},

		// Price validation
		{"zero price", &HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := 0.0; return &p }()}, true, "must be positive"},
		{"negative price", &HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := -100.0; return &p }()}, true, "must be positive"},
		{"NaN price", &HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := math.NaN(); return &p }()}, true, "NaN"},
		{"infinite price", &HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := math.Inf(1); return &p }()}, true, "infinite"},
		{"exceeds max price", &HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := float64(MaxPriceValue) + 1; return &p }()}, true, "exceeds maximum"},

		// Hash validation
		{"hash too short", &HttpRequestData{Domain: "test", TholdHash: func() *string { s := "abc"; return &s }()}, true, "invalid thold_hash length"},
		{"hash too long", &HttpRequestData{Domain: "test", TholdHash: func() *string { s := strings.Repeat("a", 41); return &s }()}, true, "invalid thold_hash length"},
		{"invalid hash chars", &HttpRequestData{Domain: "test", TholdHash: func() *string { s := strings.Repeat("g", 40); return &s }()}, true, "must be lowercase hex"},
		{"uppercase hash", &HttpRequestData{Domain: "test", TholdHash: func() *string { s := strings.Repeat("A", 40); return &s }()}, true, "must be lowercase hex"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.request == nil {
				err = (*HttpRequestData)(nil).Validate()
			} else {
				err = tt.request.Validate()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("HttpRequestData.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("HttpRequestData.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestHttpRequestDataMethods(t *testing.T) {
	price := 100000.0
	hash := strings.Repeat("a", 40)

	createReq := HttpRequestData{Domain: "test", TholdPrice: &price}
	checkReq := HttpRequestData{Domain: "test", TholdHash: &hash}

	if !createReq.IsCreateRequest() {
		t.Error("IsCreateRequest() should return true for create request")
	}
	if createReq.IsCheckRequest() {
		t.Error("IsCheckRequest() should return false for create request")
	}

	if checkReq.IsCreateRequest() {
		t.Error("IsCreateRequest() should return false for check request")
	}
	if !checkReq.IsCheckRequest() {
		t.Error("IsCheckRequest() should return true for check request")
	}
}

// =============================================================================
// EvaluateQuotesRequest Validation Tests
// =============================================================================

func TestEvaluateQuotesRequestValidate(t *testing.T) {
	validHash := strings.Repeat("a", 40)
	validHashes := []string{validHash, strings.Repeat("b", 40)}

	tests := []struct {
		name    string
		request *EvaluateQuotesRequest
		wantErr bool
		errMsg  string
	}{
		// Valid requests
		{"single hash", &EvaluateQuotesRequest{TholdHashes: []string{validHash}}, false, ""},
		{"multiple hashes", &EvaluateQuotesRequest{TholdHashes: validHashes}, false, ""},
		{"max hashes (100)", &EvaluateQuotesRequest{TholdHashes: makeHashes(100)}, false, ""},

		// Nil/empty
		{"nil request", nil, true, "request is nil"},
		{"empty hashes", &EvaluateQuotesRequest{TholdHashes: []string{}}, true, "at least one"},
		{"nil hashes", &EvaluateQuotesRequest{TholdHashes: nil}, true, "at least one"},

		// Too many
		{"too many hashes", &EvaluateQuotesRequest{TholdHashes: makeHashes(101)}, true, "max 100"},

		// Invalid hashes
		{"short hash at index 0", &EvaluateQuotesRequest{TholdHashes: []string{"abc"}}, true, "at index 0"},
		{"short hash at index 1", &EvaluateQuotesRequest{TholdHashes: []string{validHash, "abc"}}, true, "at index 1"},
		{"invalid chars at index 0", &EvaluateQuotesRequest{TholdHashes: []string{strings.Repeat("g", 40)}}, true, "at index 0"},
		{"uppercase at index 2", &EvaluateQuotesRequest{TholdHashes: []string{validHash, validHash, strings.Repeat("A", 40)}}, true, "at index 2"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.request == nil {
				err = (*EvaluateQuotesRequest)(nil).Validate()
			} else {
				err = tt.request.Validate()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("EvaluateQuotesRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("EvaluateQuotesRequest.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

// =============================================================================
// GenerateQuotesRequest Validation Tests
// =============================================================================

func TestGenerateQuotesRequestValidate(t *testing.T) {
	validRequest := GenerateQuotesRequest{
		RateMin:     1.35,
		RateMax:     5.0,
		StepSize:    0.05,
		Domain:      "test-domain",
		QuoteDomain: "quote-domain",
	}

	tests := []struct {
		name    string
		request *GenerateQuotesRequest
		wantErr bool
		errMsg  string
	}{
		// Valid
		{"valid request", &validRequest, false, ""},
		{"without quote_domain", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: "test"}, false, ""},

		// Nil
		{"nil request", nil, true, "request is nil"},

		// Rate validation
		{"zero rate_min", &GenerateQuotesRequest{RateMin: 0, RateMax: 5.0, StepSize: 0.05, Domain: "test"}, true, "rate_min must be positive"},
		{"negative rate_min", &GenerateQuotesRequest{RateMin: -1, RateMax: 5.0, StepSize: 0.05, Domain: "test"}, true, "rate_min must be positive"},
		{"zero rate_max", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 0, StepSize: 0.05, Domain: "test"}, true, "rate_max must be positive"},
		{"rate_min >= rate_max", &GenerateQuotesRequest{RateMin: 5.0, RateMax: 5.0, StepSize: 0.05, Domain: "test"}, true, "rate_min (5.0000) must be less than rate_max"},
		{"rate_min too low", &GenerateQuotesRequest{RateMin: 1.0, RateMax: 5.0, StepSize: 0.05, Domain: "test"}, true, "at least 1.01"},

		// Step size validation
		{"zero step_size", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0, Domain: "test"}, true, "step_size must be positive"},
		{"step_size too small", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.001, Domain: "test"}, true, "at least 0.01"},
		{"step_size too large", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 1.5, Domain: "test"}, true, "not exceed 1.0"},

		// Too many quotes
		{"too many quotes", &GenerateQuotesRequest{RateMin: 1.01, RateMax: 100.0, StepSize: 0.01, Domain: "test"}, true, "too many quotes"},

		// Domain validation
		{"empty domain", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: ""}, true, "domain required"},
		{"domain too long", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: strings.Repeat("a", MaxDomainLength)}, true, "domain too long"},
		{"invalid domain chars", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: "test@domain"}, true, "invalid characters"},

		// QuoteDomain validation
		{"invalid quote_domain", &GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: "test", QuoteDomain: "test@quote"}, true, "quote_domain"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.request == nil {
				err = (*GenerateQuotesRequest)(nil).Validate()
			} else {
				err = tt.request.Validate()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("GenerateQuotesRequest.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("GenerateQuotesRequest.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestGenerateQuotesRequestMethods(t *testing.T) {
	tests := []struct {
		name          string
		request       GenerateQuotesRequest
		wantNumQuotes int
		wantDomain    string
	}{
		{
			name:          "standard range",
			request:       GenerateQuotesRequest{RateMin: 1.35, RateMax: 1.50, StepSize: 0.05, Domain: "test", QuoteDomain: "quote"},
			wantNumQuotes: 3, // int((1.50-1.35)/0.05) + 1 = int(2.9999...) + 1 = 2 + 1 = 3 (floating point truncation)
			wantDomain:    "quote",
		},
		{
			name:          "single quote",
			request:       GenerateQuotesRequest{RateMin: 1.35, RateMax: 1.36, StepSize: 0.05, Domain: "test"},
			wantNumQuotes: 1,
			wantDomain:    "test", // defaults to Domain
		},
		{
			name:          "zero step size",
			request:       GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0, Domain: "test"},
			wantNumQuotes: 0,
			wantDomain:    "test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			numQuotes := tt.request.CalculateNumQuotes()
			if numQuotes != tt.wantNumQuotes {
				t.Errorf("CalculateNumQuotes() = %d, want %d", numQuotes, tt.wantNumQuotes)
			}

			domain := tt.request.GetQuoteDomain()
			if domain != tt.wantDomain {
				t.Errorf("GetQuoteDomain() = %s, want %s", domain, tt.wantDomain)
			}
		})
	}
}

// =============================================================================
// QuoteEvaluationResult Tests
// =============================================================================

func TestQuoteEvaluationResultMethods(t *testing.T) {
	breachedKey := "secret123"

	tests := []struct {
		name       string
		result     QuoteEvaluationResult
		isBreached bool
		isActive   bool
		isError    bool
	}{
		{"breached result", QuoteEvaluationResult{Status: "breached", TholdKey: &breachedKey}, true, false, false},
		{"active result", QuoteEvaluationResult{Status: "active"}, false, true, false},
		{"error result", QuoteEvaluationResult{Status: "error"}, false, false, true},
		{"unknown status", QuoteEvaluationResult{Status: "unknown"}, false, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.result.IsBreached() != tt.isBreached {
				t.Errorf("IsBreached() = %v, want %v", tt.result.IsBreached(), tt.isBreached)
			}
			if tt.result.IsActive() != tt.isActive {
				t.Errorf("IsActive() = %v, want %v", tt.result.IsActive(), tt.isActive)
			}
			if tt.result.IsError() != tt.isError {
				t.Errorf("IsError() = %v, want %v", tt.result.IsError(), tt.isError)
			}
		})
	}
}

// =============================================================================
// EvaluateQuotesResponse Tests
// =============================================================================

func TestEvaluateQuotesResponseMethods(t *testing.T) {
	key := "secret"
	errMsg := "error msg"

	response := EvaluateQuotesResponse{
		Results: []QuoteEvaluationResult{
			{Status: "breached", TholdKey: &key},
			{Status: "breached", TholdKey: &key},
			{Status: "active"},
			{Status: "active"},
			{Status: "active"},
			{Status: "error", Error: &errMsg},
		},
		CurrentPrice: 100000.0,
		EvaluatedAt:  1700000000,
	}

	if response.CountBreached() != 2 {
		t.Errorf("CountBreached() = %d, want 2", response.CountBreached())
	}
	if response.CountActive() != 3 {
		t.Errorf("CountActive() = %d, want 3", response.CountActive())
	}
	if response.CountErrors() != 1 {
		t.Errorf("CountErrors() = %d, want 1", response.CountErrors())
	}
}

// =============================================================================
// PriceEvent Tests
// =============================================================================

func TestPriceEventValidate(t *testing.T) {
	validKey := strings.Repeat("a", 64)
	validEvent := PriceEvent{
		// v2.5 fields
		SrvNetwork: "main",
		SrvPubkey:  strings.Repeat("f", 64),
		EventType:  EventTypeBreach,
		TholdHash:  strings.Repeat("b", 40),
		ReqID:      strings.Repeat("c", 64),
		ReqSig:     strings.Repeat("e", 128),
		TholdKey:   &validKey,
	}

	tests := []struct {
		name    string
		event   *PriceEvent
		wantErr bool
		errMsg  string
	}{
		{"valid breach event", &validEvent, false, ""},
		{"valid active event", func() *PriceEvent {
			e := validEvent
			e.EventType = EventTypeActive
			e.TholdKey = nil
			return &e
		}(), false, ""},

		{"nil event", nil, true, "is nil"},
		{"invalid event_type", func() *PriceEvent { e := validEvent; e.EventType = "invalid"; return &e }(), true, "invalid event_type"},
		{"invalid thold_hash", func() *PriceEvent { e := validEvent; e.TholdHash = "bad"; return &e }(), true, "invalid thold_hash"},
		{"invalid srv_pubkey", func() *PriceEvent { e := validEvent; e.SrvPubkey = "bad"; return &e }(), true, "invalid srv_pubkey"},
		{"invalid srv_network", func() *PriceEvent { e := validEvent; e.SrvNetwork = "invalid"; return &e }(), true, "invalid srv_network"},
		{"missing req_id", func() *PriceEvent { e := validEvent; e.ReqID = ""; return &e }(), true, "req_id required"},
		{"invalid req_sig", func() *PriceEvent { e := validEvent; e.ReqSig = "bad"; return &e }(), true, "invalid req_sig"},
		{"breach without key", func() *PriceEvent { e := validEvent; e.TholdKey = nil; return &e }(), true, "must have thold_key"},
		{"invalid thold_key", func() *PriceEvent {
			e := validEvent
			bad := "bad"
			e.TholdKey = &bad
			return &e
		}(), true, "invalid thold_key"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var err error
			if tt.event == nil {
				err = (*PriceEvent)(nil).Validate()
			} else {
				err = tt.event.Validate()
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("PriceEvent.Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr && tt.errMsg != "" && !strings.Contains(err.Error(), tt.errMsg) {
				t.Errorf("PriceEvent.Validate() error = %v, want error containing %q", err, tt.errMsg)
			}
		})
	}
}

func TestPriceEventMethods(t *testing.T) {
	breachEvent := PriceEvent{EventType: EventTypeBreach}
	activeEvent := PriceEvent{EventType: EventTypeActive}

	if !breachEvent.IsBreached() {
		t.Error("IsBreached() should return true for breach event")
	}
	if breachEvent.IsActive() {
		t.Error("IsActive() should return false for breach event")
	}

	if activeEvent.IsBreached() {
		t.Error("IsBreached() should return false for active event")
	}
	if !activeEvent.IsActive() {
		t.Error("IsActive() should return true for active event")
	}
}

// =============================================================================
// NostrEvent Tests
// =============================================================================

func TestNostrEventGetTag(t *testing.T) {
	event := NostrEvent{
		Tags: [][]string{
			{"d", "hash123"},
			{"domain", "test-domain"},
			{"event_type", "active"},
			{"multi", "value1"},
			{"multi", "value2"},
		},
	}

	tests := []struct {
		name    string
		tagName string
		want    string
	}{
		{"existing tag", "d", "hash123"},
		{"domain tag", "domain", "test-domain"},
		{"event_type tag", "event_type", "active"},
		{"multi tag (first value)", "multi", "value1"},
		{"non-existing tag", "nonexistent", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := event.GetTag(tt.tagName)
			if got != tt.want {
				t.Errorf("GetTag(%q) = %q, want %q", tt.tagName, got, tt.want)
			}
		})
	}
}

func TestNostrEventGetAllTagValues(t *testing.T) {
	event := NostrEvent{
		Tags: [][]string{
			{"d", "hash123"},
			{"multi", "value1"},
			{"multi", "value2"},
			{"multi", "value3"},
		},
	}

	tests := []struct {
		name    string
		tagName string
		want    []string
	}{
		{"single value tag", "d", []string{"hash123"}},
		{"multi value tag", "multi", []string{"value1", "value2", "value3"}},
		{"non-existing tag", "nonexistent", nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := event.GetAllTagValues(tt.tagName)
			if len(got) != len(tt.want) {
				t.Errorf("GetAllTagValues(%q) returned %d values, want %d", tt.tagName, len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("GetAllTagValues(%q)[%d] = %q, want %q", tt.tagName, i, got[i], tt.want[i])
				}
			}
		})
	}
}

// =============================================================================
// JSON Serialization Tests
// =============================================================================

func TestTypesJSONSerialization(t *testing.T) {
	key := "secret123"

	types := []interface{}{
		Config{ClientID: "test", DataStreamURL: "url", FeedID: "feed", RelayURL: "relay", Network: "net"},
		HttpRequestData{Domain: "test", TholdPrice: func() *float64 { p := 100.0; return &p }()},
		EvaluateQuotesRequest{TholdHashes: []string{"hash1", "hash2"}},
		GenerateQuotesRequest{RateMin: 1.35, RateMax: 5.0, StepSize: 0.05, Domain: "test"},
		QuoteEvaluationResult{TholdHash: "hash", Status: "breached", TholdKey: &key, CurrentPrice: 100.0, TholdPrice: 90.0},
		EvaluateQuotesResponse{Results: []QuoteEvaluationResult{{Status: "active"}}, CurrentPrice: 100.0, EvaluatedAt: 123},
		PriceEvent{EventType: EventTypeActive, TholdHash: "hash", TholdPrice: 100.0},
		NostrEvent{ID: "id", PubKey: "pubkey", CreatedAt: 123, Kind: 30078},
		RelayResponse{Success: true, Message: "ok"},
	}

	for i, typ := range types {
		t.Run("type_"+string(rune('A'+i)), func(t *testing.T) {
			jsonData, err := json.Marshal(typ)
			if err != nil {
				t.Fatalf("Failed to marshal: %v", err)
			}
			if len(jsonData) == 0 {
				t.Error("Marshal produced empty JSON")
			}
		})
	}
}

// =============================================================================
// Helper Functions
// =============================================================================

func makeHashes(n int) []string {
	hashes := make([]string, n)
	for i := 0; i < n; i++ {
		hashes[i] = strings.Repeat("a", 40)
	}
	return hashes
}

// =============================================================================
// Benchmark Tests
// =============================================================================

func BenchmarkConfigValidate(b *testing.B) {
	config := Config{
		ClientID:      "test-client",
		DataStreamURL: "https://data.example.com",
		FeedID:        "feed-123",
		RelayURL:      "wss://relay.example.com",
		Network:       "mutiny",
		AuthorizedKey: "0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		config.Validate()
	}
}

func BenchmarkHttpRequestDataValidate(b *testing.B) {
	price := 100000.0
	req := HttpRequestData{Domain: "test-domain", TholdPrice: &price}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Validate()
	}
}

func BenchmarkEvaluateQuotesRequestValidate(b *testing.B) {
	req := EvaluateQuotesRequest{TholdHashes: makeHashes(50)}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Validate()
	}
}

func BenchmarkGenerateQuotesRequestValidate(b *testing.B) {
	req := GenerateQuotesRequest{
		RateMin:  1.35,
		RateMax:  5.0,
		StepSize: 0.05,
		Domain:   "test-domain",
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		req.Validate()
	}
}

func BenchmarkPriceEventValidate(b *testing.B) {
	key := strings.Repeat("a", 64)
	event := PriceEvent{
		// v2.5 fields
		SrvNetwork: "main",
		SrvPubkey:  strings.Repeat("f", 64),
		EventType:  EventTypeBreach,
		TholdHash:  strings.Repeat("b", 40),
		ReqID:      strings.Repeat("c", 64),
		ReqSig:     strings.Repeat("e", 128),
		TholdKey:   &key,
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event.Validate()
	}
}
