package crypto

import (
	"testing"
)

// Test vectors using known values
const (
	testPrivateKey = "8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e"
	testDomain     = "test.example.com"
)

func TestDeriveKeys(t *testing.T) {
	tests := []struct {
		name    string
		privKey string
		wantErr bool
	}{
		{
			name:    "valid private key",
			privKey: testPrivateKey,
			wantErr: false,
		},
		{
			name:    "invalid hex",
			privKey: "invalid_hex",
			wantErr: true,
		},
		{
			name:    "wrong length",
			privKey: "abcdef",
			wantErr: true,
		},
		{
			name:    "empty key",
			privKey: "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			kd, err := DeriveKeys(tt.privKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("DeriveKeys() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if kd == nil {
					t.Error("DeriveKeys() returned nil KeyDerivation")
				}
				if len(kd.SchnorrPubkey) != 64 {
					t.Errorf("SchnorrPubkey length = %d, want 64", len(kd.SchnorrPubkey))
				}
			}
		})
	}
}

func TestGetServerHMAC(t *testing.T) {
	tests := []struct {
		name    string
		privKey string
		domain  string
		wantErr bool
	}{
		{
			name:    "valid inputs",
			privKey: testPrivateKey,
			domain:  testDomain,
			wantErr: false,
		},
		{
			name:    "empty domain",
			privKey: testPrivateKey,
			domain:  "",
			wantErr: true,
		},
		{
			name:    "invalid hex key",
			privKey: "invalid",
			domain:  testDomain,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hmac1, err := GetServerHMAC(tt.privKey, tt.domain)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetServerHMAC() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(hmac1) != 64 {
					t.Errorf("HMAC length = %d, want 64", len(hmac1))
				}

				// Test determinism
				hmac2, _ := GetServerHMAC(tt.privKey, tt.domain)
				if hmac1 != hmac2 {
					t.Error("GetServerHMAC() is not deterministic")
				}

				// Test domain separation
				hmac3, _ := GetServerHMAC(tt.privKey, "different.domain")
				if hmac1 == hmac3 {
					t.Error("GetServerHMAC() does not separate by domain")
				}
			}
		})
	}
}

func TestGetThresholdKey(t *testing.T) {
	serverHMAC := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"

	tests := []struct {
		name       string
		serverHMAC string
		domain     string
		quotePrice float64
		quoteStamp int64
		tholdPrice float64
		wantErr    bool
	}{
		{
			name:       "valid inputs",
			serverHMAC: serverHMAC,
			domain:     testDomain,
			quotePrice: 50000.0,
			quoteStamp: 1700000000,
			tholdPrice: 45000.0,
			wantErr:    false,
		},
		{
			name:       "empty domain",
			serverHMAC: serverHMAC,
			domain:     "",
			quotePrice: 50000.0,
			quoteStamp: 1700000000,
			tholdPrice: 45000.0,
			wantErr:    true,
		},
		{
			name:       "negative quote price",
			serverHMAC: serverHMAC,
			domain:     testDomain,
			quotePrice: -50000.0,
			quoteStamp: 1700000000,
			tholdPrice: 45000.0,
			wantErr:    true,
		},
		{
			name:       "zero threshold price",
			serverHMAC: serverHMAC,
			domain:     testDomain,
			quotePrice: 50000.0,
			quoteStamp: 1700000000,
			tholdPrice: 0,
			wantErr:    true,
		},
		{
			name:       "negative timestamp",
			serverHMAC: serverHMAC,
			domain:     testDomain,
			quotePrice: 50000.0,
			quoteStamp: -1,
			tholdPrice: 45000.0,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := GetThresholdKey(tt.serverHMAC, tt.domain, tt.quotePrice, tt.quoteStamp, tt.tholdPrice)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetThresholdKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(key1) != 64 {
					t.Errorf("ThresholdKey length = %d, want 64", len(key1))
				}

				// Test determinism
				key2, _ := GetThresholdKey(tt.serverHMAC, tt.domain, tt.quotePrice, tt.quoteStamp, tt.tholdPrice)
				if key1 != key2 {
					t.Error("GetThresholdKey() is not deterministic")
				}

				// Test parameter binding
				key3, _ := GetThresholdKey(tt.serverHMAC, tt.domain, tt.quotePrice+1, tt.quoteStamp, tt.tholdPrice)
				if key1 == key3 {
					t.Error("GetThresholdKey() does not bind to quotePrice")
				}
			}
		})
	}
}

func TestHash160(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
		wantLen int
	}{
		{
			name:    "valid data",
			data:    []byte("test data"),
			wantErr: false,
			wantLen: 40,
		},
		{
			name:    "empty data",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1, err := Hash160(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash160() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(hash1) != tt.wantLen {
					t.Errorf("Hash160() length = %d, want %d", len(hash1), tt.wantLen)
				}

				// Test determinism
				hash2, _ := Hash160(tt.data)
				if hash1 != hash2 {
					t.Error("Hash160() is not deterministic")
				}

				// Test different inputs produce different hashes
				hash3, _ := Hash160([]byte("different data"))
				if hash1 == hash3 {
					t.Error("Hash160() collision detected")
				}
			}
		})
	}
}

func TestVerifyThresholdCommitment(t *testing.T) {
	secret := "test_secret_value"
	correctHash, _ := Hash160([]byte(secret))
	wrongHash := "0000000000000000000000000000000000000000"

	tests := []struct {
		name    string
		secret  string
		hash    string
		wantErr bool
	}{
		{
			name:    "valid commitment",
			secret:  secret,
			hash:    correctHash,
			wantErr: false,
		},
		{
			name:    "wrong hash",
			secret:  secret,
			hash:    wrongHash,
			wantErr: true,
		},
		{
			name:    "empty secret",
			secret:  "",
			hash:    correctHash,
			wantErr: true,
		},
		{
			name:    "empty hash",
			secret:  secret,
			hash:    "",
			wantErr: true,
		},
		{
			name:    "invalid hash length",
			secret:  secret,
			hash:    "abc123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyThresholdCommitment(tt.secret, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyThresholdCommitment() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestComputeRequestID(t *testing.T) {
	preimage1 := []interface{}{"domain", "network", "pubkey", 50000.0, 1700000000}
	preimage2 := []interface{}{"domain", "network", "pubkey", 50000.0, 1700000001}

	tests := []struct {
		name     string
		preimage []interface{}
		wantErr  bool
	}{
		{
			name:     "valid preimage",
			preimage: preimage1,
			wantErr:  false,
		},
		{
			name:     "nil preimage",
			preimage: nil,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqID1, err := ComputeRequestID(tt.preimage)
			if (err != nil) != tt.wantErr {
				t.Errorf("ComputeRequestID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(reqID1) != 64 {
					t.Errorf("RequestID length = %d, want 64", len(reqID1))
				}

				// Test determinism
				reqID2, _ := ComputeRequestID(tt.preimage)
				if reqID1 != reqID2 {
					t.Error("ComputeRequestID() is not deterministic")
				}

				// Test different preimages produce different IDs
				reqID3, _ := ComputeRequestID(preimage2)
				if reqID1 == reqID3 {
					t.Error("ComputeRequestID() collision detected")
				}
			}
		})
	}
}

func TestSignSchnorr(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)
	message := "0000000000000000000000000000000000000000000000000000000000000001"

	tests := []struct {
		name    string
		privKey []byte
		message string
		wantErr bool
	}{
		{
			name:    "valid signature",
			privKey: kd.PrivateKey,
			message: message,
			wantErr: false,
		},
		{
			name:    "invalid key length",
			privKey: []byte{0x01, 0x02},
			message: message,
			wantErr: true,
		},
		{
			name:    "invalid message hex",
			privKey: kd.PrivateKey,
			message: "invalid_hex",
			wantErr: true,
		},
		{
			name:    "invalid message length",
			privKey: kd.PrivateKey,
			message: "abcd",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig, err := SignSchnorr(tt.privKey, tt.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("SignSchnorr() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(sig) != 128 {
					t.Errorf("Signature length = %d, want 128", len(sig))
				}

				// Verify signature
				err = VerifySchnorrSignature(kd.SchnorrPubkey, tt.message, sig)
				if err != nil {
					t.Errorf("Signature verification failed: %v", err)
				}
			}
		})
	}
}

func TestValidateQuoteAge(t *testing.T) {
	currentTime := int64(1700000000)
	maxAge := int64(3600)

	tests := []struct {
		name        string
		quoteStamp  int64
		currentTime int64
		maxAge      int64
		wantErr     bool
	}{
		{
			name:        "fresh quote",
			quoteStamp:  currentTime - 1800,
			currentTime: currentTime,
			maxAge:      maxAge,
			wantErr:     false,
		},
		{
			name:        "expired quote",
			quoteStamp:  currentTime - 7200,
			currentTime: currentTime,
			maxAge:      maxAge,
			wantErr:     true,
		},
		{
			name:        "future timestamp",
			quoteStamp:  currentTime + 100,
			currentTime: currentTime,
			maxAge:      maxAge,
			wantErr:     true,
		},
		{
			name:        "negative quote stamp",
			quoteStamp:  -1,
			currentTime: currentTime,
			maxAge:      maxAge,
			wantErr:     true,
		},
		{
			name:        "negative current time",
			quoteStamp:  currentTime,
			currentTime: -1,
			maxAge:      maxAge,
			wantErr:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateQuoteAge(tt.quoteStamp, tt.currentTime, tt.maxAge)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateQuoteAge() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Benchmark tests
func BenchmarkDeriveKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DeriveKeys(testPrivateKey)
	}
}

func BenchmarkGetServerHMAC(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = GetServerHMAC(testPrivateKey, testDomain)
	}
}

func BenchmarkHash160(b *testing.B) {
	data := []byte("benchmark data for hash160 function")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Hash160(data)
	}
}

func BenchmarkSignSchnorr(b *testing.B) {
	kd, _ := DeriveKeys(testPrivateKey)
	message := "0000000000000000000000000000000000000000000000000000000000000001"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = SignSchnorr(kd.PrivateKey, message)
	}
}
