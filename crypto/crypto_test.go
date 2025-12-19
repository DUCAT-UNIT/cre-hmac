package crypto

import (
	"encoding/binary"
	"testing"
)

// Test vectors using known values
const (
	testPrivateKey = "8ce73a2db5cbaf4b0ab3cabece9408e3b898c64474c0dbe27826c65d1180370e"
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
					t.Fatal("DeriveKeys() returned nil KeyDerivation")
				}
				if len(kd.SchnorrPubkey) != 64 {
					t.Errorf("SchnorrPubkey length = %d, want 64", len(kd.SchnorrPubkey))
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
	// Secret is a hex string (like thold_key from HMAC)
	secretHex := "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
	secretBytes, _ := HexToBytes(secretHex)
	correctHash, _ := Hash160(secretBytes)
	wrongHash := "0000000000000000000000000000000000000000"

	tests := []struct {
		name    string
		secret  string
		hash    string
		wantErr bool
	}{
		{
			name:    "valid commitment",
			secret:  secretHex,
			hash:    correctHash,
			wantErr: false,
		},
		{
			name:    "wrong hash",
			secret:  secretHex,
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
			secret:  secretHex,
			hash:    "",
			wantErr: true,
		},
		{
			name:    "invalid hash length",
			secret:  secretHex,
			hash:    "abc123",
			wantErr: true,
		},
		{
			name:    "invalid secret hex",
			secret:  "not_valid_hex",
			hash:    correctHash,
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

// ValidateQuoteAge tests removed - function moved to shared/validation.go
// See shared/validation_test.go for comprehensive tests

// Tests for new core-ts aligned functions

func TestHash340(t *testing.T) {
	tests := []struct {
		name string
		tag  string
		data []byte
	}{
		{
			name: "price commit hash tag",
			tag:  TagPriceCommitHash,
			data: []byte("test data"),
		},
		{
			name: "price contract id tag",
			tag:  TagPriceContractID,
			data: []byte("test data"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1 := Hash340(tt.tag, tt.data)
			if len(hash1) != 32 {
				t.Errorf("Hash340() length = %d, want 32", len(hash1))
			}

			// Test determinism
			hash2 := Hash340(tt.tag, tt.data)
			if string(hash1) != string(hash2) {
				t.Error("Hash340() is not deterministic")
			}

			// Test different tags produce different hashes
			hash3 := Hash340("different/tag", tt.data)
			if string(hash1) == string(hash3) {
				t.Error("Hash340() does not separate by tag")
			}

			// Test different data produces different hashes
			hash4 := Hash340(tt.tag, []byte("different data"))
			if string(hash1) == string(hash4) {
				t.Error("Hash340() does not separate by data")
			}
		})
	}
}

func TestGetPriceCommitHash(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)

	tests := []struct {
		name       string
		obs        PriceObservation
		tholdPrice uint32
		wantErr    bool
	}{
		{
			name: "valid inputs",
			obs: PriceObservation{
				OraclePubkey: kd.SchnorrPubkey,
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    1700000000,
			},
			tholdPrice: 90000,
			wantErr:    false,
		},
		{
			name: "invalid pubkey",
			obs: PriceObservation{
				OraclePubkey: "invalid",
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    1700000000,
			},
			tholdPrice: 90000,
			wantErr:    true,
		},
		{
			name: "wrong pubkey length",
			obs: PriceObservation{
				OraclePubkey: "abcd1234",
				ChainNetwork: "mutiny",
				BasePrice:    100000,
				BaseStamp:    1700000000,
			},
			tholdPrice: 90000,
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash1, err := GetPriceCommitHash(tt.obs, tt.tholdPrice)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPriceCommitHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(hash1) != 64 {
					t.Errorf("CommitHash length = %d, want 64", len(hash1))
				}

				// Test determinism
				hash2, _ := GetPriceCommitHash(tt.obs, tt.tholdPrice)
				if hash1 != hash2 {
					t.Error("GetPriceCommitHash() is not deterministic")
				}

				// Test different threshold produces different hash
				hash3, _ := GetPriceCommitHash(tt.obs, tt.tholdPrice+1)
				if hash1 == hash3 {
					t.Error("GetPriceCommitHash() does not bind to tholdPrice")
				}
			}
		})
	}
}

func TestGetTholdKey(t *testing.T) {
	validCommitHash := "0000000000000000000000000000000000000000000000000000000000000001"

	tests := []struct {
		name         string
		oracleSeckey string
		commitHash   string
		wantErr      bool
	}{
		{
			name:         "valid inputs",
			oracleSeckey: testPrivateKey,
			commitHash:   validCommitHash,
			wantErr:      false,
		},
		{
			name:         "invalid seckey",
			oracleSeckey: "invalid",
			commitHash:   validCommitHash,
			wantErr:      true,
		},
		{
			name:         "invalid commit hash",
			oracleSeckey: testPrivateKey,
			commitHash:   "invalid",
			wantErr:      true,
		},
		{
			name:         "wrong commit hash length",
			oracleSeckey: testPrivateKey,
			commitHash:   "abcd",
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key1, err := GetTholdKey(tt.oracleSeckey, tt.commitHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetTholdKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(key1) != 64 {
					t.Errorf("TholdKey length = %d, want 64", len(key1))
				}

				// Test determinism
				key2, _ := GetTholdKey(tt.oracleSeckey, tt.commitHash)
				if key1 != key2 {
					t.Error("GetTholdKey() is not deterministic")
				}
			}
		})
	}
}

func TestGetPriceContractID(t *testing.T) {
	validCommitHash := "0000000000000000000000000000000000000000000000000000000000000001"
	validTholdHash := "0000000000000000000000000000000000000000"

	tests := []struct {
		name       string
		commitHash string
		tholdHash  string
		wantErr    bool
	}{
		{
			name:       "valid inputs",
			commitHash: validCommitHash,
			tholdHash:  validTholdHash,
			wantErr:    false,
		},
		{
			name:       "invalid commit hash",
			commitHash: "invalid",
			tholdHash:  validTholdHash,
			wantErr:    true,
		},
		{
			name:       "invalid thold hash",
			commitHash: validCommitHash,
			tholdHash:  "invalid",
			wantErr:    true,
		},
		{
			name:       "wrong thold hash length",
			commitHash: validCommitHash,
			tholdHash:  "abcd",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id1, err := GetPriceContractID(tt.commitHash, tt.tholdHash)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetPriceContractID() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(id1) != 64 {
					t.Errorf("ContractID length = %d, want 64", len(id1))
				}

				// Test determinism
				id2, _ := GetPriceContractID(tt.commitHash, tt.tholdHash)
				if id1 != id2 {
					t.Error("GetPriceContractID() is not deterministic")
				}
			}
		})
	}
}

func TestCreatePriceContract(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)

	obs := PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    100000,
		BaseStamp:    1700000000,
	}

	contract, err := CreatePriceContract(testPrivateKey, obs, 90000)
	if err != nil {
		t.Fatalf("CreatePriceContract() error = %v", err)
	}

	// Verify all fields are populated
	if contract.BasePrice != obs.BasePrice {
		t.Errorf("BasePrice = %d, want %d", contract.BasePrice, obs.BasePrice)
	}
	if contract.BaseStamp != obs.BaseStamp {
		t.Errorf("BaseStamp = %d, want %d", contract.BaseStamp, obs.BaseStamp)
	}
	if contract.ChainNetwork != obs.ChainNetwork {
		t.Errorf("ChainNetwork = %s, want %s", contract.ChainNetwork, obs.ChainNetwork)
	}
	if contract.OraclePubkey != obs.OraclePubkey {
		t.Errorf("OraclePubkey = %s, want %s", contract.OraclePubkey, obs.OraclePubkey)
	}
	if contract.TholdPrice != 90000 {
		t.Errorf("TholdPrice = %d, want 90000", contract.TholdPrice)
	}
	if len(contract.CommitHash) != 64 {
		t.Errorf("CommitHash length = %d, want 64", len(contract.CommitHash))
	}
	if len(contract.ContractID) != 64 {
		t.Errorf("ContractID length = %d, want 64", len(contract.ContractID))
	}
	if len(contract.TholdHash) != 40 {
		t.Errorf("TholdHash length = %d, want 40", len(contract.TholdHash))
	}
	if contract.TholdKey == nil || len(*contract.TholdKey) != 64 {
		t.Errorf("TholdKey should be 64 hex chars")
	}
	if len(contract.OracleSig) != 128 {
		t.Errorf("OracleSig length = %d, want 128", len(contract.OracleSig))
	}
}

func TestVerifyPriceContract(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)

	obs := PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    100000,
		BaseStamp:    1700000000,
	}

	contract, _ := CreatePriceContract(testPrivateKey, obs, 90000)

	// Test valid contract verification
	if err := VerifyPriceContract(contract); err != nil {
		t.Errorf("VerifyPriceContract() on valid contract error = %v", err)
	}

	// Test nil contract
	if err := VerifyPriceContract(nil); err == nil {
		t.Error("VerifyPriceContract() should fail on nil contract")
	}

	// Test tampered contract
	tampered := *contract
	tampered.TholdPrice = 80000
	if err := VerifyPriceContract(&tampered); err == nil {
		t.Error("VerifyPriceContract() should fail on tampered contract")
	}
}

// Additional tests for uncovered functions

func TestHexToBytes(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantLen int
		wantErr bool
	}{
		{"valid hex", "abcdef", 3, false},
		{"invalid hex", "xyz", 0, true},
		{"empty", "", 0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := HexToBytes(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("HexToBytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantLen {
				t.Errorf("HexToBytes() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestBytesToHex(t *testing.T) {
	input := []byte{0xab, 0xcd, 0xef}
	expected := "abcdef"
	result := BytesToHex(input)
	if result != expected {
		t.Errorf("BytesToHex() = %s, want %s", result, expected)
	}
}

func TestGetPublicKey(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)
	pubkey := GetPublicKey(kd.PrivateKey)
	if len(pubkey) != 32 {
		t.Errorf("GetPublicKey() len = %d, want 32", len(pubkey))
	}
	// Verify it matches the derived pubkey
	if BytesToHex(pubkey) != kd.SchnorrPubkey {
		t.Error("GetPublicKey() does not match DeriveKeys().SchnorrPubkey")
	}
}

func TestHash160Bytes(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantLen int
		wantErr bool
	}{
		{"valid data", []byte("test"), 20, false},
		{"empty data", []byte{}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := Hash160Bytes(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("Hash160Bytes() error = %v, wantErr %v", err, tt.wantErr)
			}
			if !tt.wantErr && len(result) != tt.wantLen {
				t.Errorf("Hash160Bytes() len = %d, want %d", len(result), tt.wantLen)
			}
		})
	}
}

func TestVerifySchnorrEventSignature(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)
	message := "0000000000000000000000000000000000000000000000000000000000000001"
	sig, _ := SignSchnorr(kd.PrivateKey, message)

	tests := []struct {
		name    string
		pubkey  string
		eventID string
		sig     string
		wantErr bool
	}{
		{"valid signature", kd.SchnorrPubkey, message, sig, false},
		{"invalid pubkey hex", "invalid", message, sig, true},
		{"invalid sig hex", kd.SchnorrPubkey, message, "invalid", true},
		{"invalid eventID hex", kd.SchnorrPubkey, "invalid", sig, true},
		{"wrong signature", kd.SchnorrPubkey, message, "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySchnorrEventSignature(tt.pubkey, tt.eventID, tt.sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySchnorrEventSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifySchnorrSignature_ErrorPaths(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)
	message := "0000000000000000000000000000000000000000000000000000000000000001"
	sig, _ := SignSchnorr(kd.PrivateKey, message)

	tests := []struct {
		name    string
		pubkey  string
		msg     string
		sig     string
		wantErr bool
	}{
		{"invalid pubkey length", "abcd", message, sig, true},
		{"invalid message length", kd.SchnorrPubkey, "abcd", sig, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySchnorrSignature(tt.pubkey, tt.msg, tt.sig)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifySchnorrSignature() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestCreatePriceContract_ErrorPaths(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)

	tests := []struct {
		name       string
		seckey     string
		pubkey     string
		network    string
		basePrice  uint32
		baseStamp  uint32
		tholdPrice uint32
		wantErr    bool
	}{
		{"invalid seckey", "invalid", kd.SchnorrPubkey, "mutiny", 100000, 1700000000, 90000, true},
		{"invalid pubkey", testPrivateKey, "invalid", "mutiny", 100000, 1700000000, 90000, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obs := PriceObservation{
				OraclePubkey: tt.pubkey,
				ChainNetwork: tt.network,
				BasePrice:    tt.basePrice,
				BaseStamp:    tt.baseStamp,
			}
			_, err := CreatePriceContract(tt.seckey, obs, tt.tholdPrice)
			if (err != nil) != tt.wantErr {
				t.Errorf("CreatePriceContract() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestVerifyPriceContract_ErrorPaths(t *testing.T) {
	kd, _ := DeriveKeys(testPrivateKey)

	obs := PriceObservation{
		OraclePubkey: kd.SchnorrPubkey,
		ChainNetwork: "mutiny",
		BasePrice:    100000,
		BaseStamp:    1700000000,
	}

	validContract, _ := CreatePriceContract(testPrivateKey, obs, 90000)

	// Test signature verification failure
	badSigContract := *validContract
	badSigContract.OracleSig = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"

	tests := []struct {
		name     string
		contract *PriceContract
		wantErr  bool
	}{
		{"bad signature", &badSigContract, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyPriceContract(tt.contract)
			if (err != nil) != tt.wantErr {
				t.Errorf("VerifyPriceContract() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// Cross-implementation test vectors
// These vectors can be used to verify Go produces identical output to TypeScript core-ts
//
// To generate new vectors from TypeScript:
//   import { create_price_contract, get_price_commit_hash } from '@ducat-unit/core/lib'
//   import { hmac256, hash160, hash340 } from '@vbyte/micro-lib/hash'

func TestCrossImplementationVectors(t *testing.T) {
	// Fixed test data that matches TypeScript core-ts implementation
	// These expected values are derived from TypeScript and serve as golden reference
	oracleSeckey := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"

	// Static expected values from TypeScript core-ts
	// These MUST match TypeScript output exactly - any mismatch indicates a cross-impl bug
	const (
		expectedPubkey     = "d8a918b3bebca63fc03fcd1d3c7c15a08cf44464f27dd3a5bb442653ba470cd5"
		expectedCommitHash = "a5d5969090854207aa412937aafb1e4d2d08e428669ea7089d71626016fc6eb1"
		expectedTholdKey   = "ffa2177841c0773548cdfe08d8ad9730a1689dd7344b79c73ebb6b6d297e304c"
		expectedTholdHash  = "81c787eb88db038d6a1fa7964295dc35e06877da"
		expectedContractID = "820cccc8f8df4c96c17f3aacae50411272871e17f36d85a8976c81a7897b61ef"
	)

	kd, err := DeriveKeys(oracleSeckey)
	if err != nil {
		t.Fatalf("Failed to derive keys: %v", err)
	}
	oraclePubkey := kd.SchnorrPubkey

	// Verify pubkey matches expected
	if oraclePubkey != expectedPubkey {
		t.Errorf("Public key mismatch:\n  got:  %s\n  want: %s", oraclePubkey, expectedPubkey)
	}
	t.Logf("Oracle pubkey: %s", oraclePubkey)

	chainNetwork := "mutiny"
	var basePrice uint32 = 100000
	var baseStamp uint32 = 1700000000
	var tholdPrice uint32 = 90000

	// Test GetPriceCommitHash
	obs := PriceObservation{
		OraclePubkey: oraclePubkey,
		ChainNetwork: chainNetwork,
		BasePrice:    basePrice,
		BaseStamp:    baseStamp,
	}
	commitHash, err := GetPriceCommitHash(obs, tholdPrice)
	if err != nil {
		t.Fatalf("GetPriceCommitHash failed: %v", err)
	}
	if commitHash != expectedCommitHash {
		t.Errorf("CommitHash mismatch:\n  got:  %s\n  want: %s", commitHash, expectedCommitHash)
	}
	t.Logf("CommitHash: %s", commitHash)

	// Test GetTholdKey
	tholdKey, err := GetTholdKey(oracleSeckey, commitHash)
	if err != nil {
		t.Fatalf("GetTholdKey failed: %v", err)
	}
	if tholdKey != expectedTholdKey {
		t.Errorf("TholdKey mismatch:\n  got:  %s\n  want: %s", tholdKey, expectedTholdKey)
	}
	t.Logf("TholdKey: %s", tholdKey)

	// Test Hash160 (thold_hash)
	tholdKeyBytes, _ := HexToBytes(tholdKey)
	tholdHash, err := Hash160(tholdKeyBytes)
	if err != nil {
		t.Fatalf("Hash160 failed: %v", err)
	}
	if tholdHash != expectedTholdHash {
		t.Errorf("TholdHash mismatch:\n  got:  %s\n  want: %s", tholdHash, expectedTholdHash)
	}
	t.Logf("TholdHash: %s", tholdHash)

	// Test GetPriceContractID
	contractID, err := GetPriceContractID(commitHash, tholdHash)
	if err != nil {
		t.Fatalf("GetPriceContractID failed: %v", err)
	}
	if contractID != expectedContractID {
		t.Errorf("ContractID mismatch:\n  got:  %s\n  want: %s", contractID, expectedContractID)
	}
	t.Logf("ContractID: %s", contractID)

	// Verify full contract creation matches
	contract, err := CreatePriceContract(oracleSeckey, obs, tholdPrice)
	if err != nil {
		t.Fatalf("CreatePriceContract failed: %v", err)
	}

	if contract.CommitHash != expectedCommitHash {
		t.Errorf("Contract CommitHash mismatch: got %s, want %s", contract.CommitHash, expectedCommitHash)
	}
	if contract.TholdHash != expectedTholdHash {
		t.Errorf("Contract TholdHash mismatch: got %s, want %s", contract.TholdHash, expectedTholdHash)
	}
	if contract.ContractID != expectedContractID {
		t.Errorf("Contract ContractID mismatch: got %s, want %s", contract.ContractID, expectedContractID)
	}
	if contract.TholdKey == nil || *contract.TholdKey != expectedTholdKey {
		t.Errorf("Contract TholdKey mismatch")
	}

	// Print all values for cross-implementation verification
	t.Logf("\n=== Cross-Implementation Test Vectors ===")
	t.Logf("Input:")
	t.Logf("  oracle_seckey:  %s", oracleSeckey)
	t.Logf("  oracle_pubkey:  %s", oraclePubkey)
	t.Logf("  chain_network:  %s", chainNetwork)
	t.Logf("  base_price:     %d", basePrice)
	t.Logf("  base_stamp:     %d", baseStamp)
	t.Logf("  thold_price:    %d", tholdPrice)
	t.Logf("Output:")
	t.Logf("  commit_hash:    %s", commitHash)
	t.Logf("  thold_key:      %s", tholdKey)
	t.Logf("  thold_hash:     %s", tholdHash)
	t.Logf("  contract_id:    %s", contractID)
	t.Logf("  oracle_sig:     %s", contract.OracleSig)
	t.Logf("==========================================\n")
}

// Test preimage encoding matches TypeScript Buff.join behavior
func TestPreimageEncoding(t *testing.T) {
	// Test that we encode numbers as big-endian 4 bytes (matching Buff.num(value, 4))
	// Buff.num uses big-endian by default (no .reverse())

	// Test case: value 100000 (0x186A0) as 4 bytes big-endian = [0x00, 0x01, 0x86, 0xA0]
	var value uint32 = 100000
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, value)

	expected := []byte{0x00, 0x01, 0x86, 0xA0}
	if !bytesEqual(buf, expected) {
		t.Errorf("100000 encoding: got %x, want %x", buf, expected)
	}

	// Test case: value 1700000000 (0x6553F100) as 4 bytes big-endian
	var stamp uint32 = 1700000000
	buf2 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf2, stamp)

	expected2 := []byte{0x65, 0x53, 0xF1, 0x00}
	if !bytesEqual(buf2, expected2) {
		t.Errorf("1700000000 encoding: got %x, want %x", buf2, expected2)
	}

	// Test case: value 90000 (0x15F90) as 4 bytes big-endian
	var thold uint32 = 90000
	buf3 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf3, thold)

	expected3 := []byte{0x00, 0x01, 0x5F, 0x90}
	if !bytesEqual(buf3, expected3) {
		t.Errorf("90000 encoding: got %x, want %x", buf3, expected3)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Benchmark tests
func BenchmarkDeriveKeys(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = DeriveKeys(testPrivateKey)
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

// TestVerifySchnorrSignatureMalleability tests that the verification function properly
// rejects malformed or potentially malleable signatures.
//
// BIP-340 Schnorr signatures have specific properties that prevent malleability:
// - The signature is exactly 64 bytes (r, s)
// - The public key is exactly 32 bytes (x-only)
// - The message hash is exactly 32 bytes
func TestVerifySchnorrSignatureMalleability(t *testing.T) {
	kd, err := DeriveKeys(testPrivateKey)
	if err != nil {
		t.Fatalf("DeriveKeys failed: %v", err)
	}

	// Create a valid signature
	message := "0000000000000000000000000000000000000000000000000000000000000001"
	sig, err := SignSchnorr(kd.PrivateKey, message)
	if err != nil {
		t.Fatalf("SignSchnorr failed: %v", err)
	}

	// Verify valid signature works
	if err := VerifySchnorrSignature(kd.SchnorrPubkey, message, sig); err != nil {
		t.Errorf("Valid signature should verify: %v", err)
	}

	tests := []struct {
		name      string
		pubkey    string
		message   string
		signature string
		wantErr   string
	}{
		{
			name:      "truncated signature (60 bytes instead of 64)",
			pubkey:    kd.SchnorrPubkey,
			message:   message,
			signature: sig[:120], // 60 bytes in hex = 120 chars
			wantErr:   "invalid signature length",
		},
		{
			name:      "extended signature (68 bytes instead of 64)",
			pubkey:    kd.SchnorrPubkey,
			message:   message,
			signature: sig + "00000000", // 68 bytes in hex
			wantErr:   "invalid signature length",
		},
		{
			name:      "truncated public key (28 bytes instead of 32)",
			pubkey:    kd.SchnorrPubkey[:56], // 28 bytes in hex = 56 chars
			message:   message,
			signature: sig,
			wantErr:   "invalid public key length",
		},
		{
			name:      "truncated message (28 bytes instead of 32)",
			pubkey:    kd.SchnorrPubkey,
			message:   message[:56], // 28 bytes in hex = 56 chars
			signature: sig,
			wantErr:   "invalid message length",
		},
		{
			name:      "bit-flipped signature (r component modified)",
			pubkey:    kd.SchnorrPubkey,
			message:   message,
			signature: flipBit(sig, 0), // Flip first byte
			wantErr:   "signature verification failed",
		},
		{
			name:      "bit-flipped signature (s component modified)",
			pubkey:    kd.SchnorrPubkey,
			message:   message,
			signature: flipBit(sig, 33), // Flip byte at position 33 (in the s component)
			wantErr:   "signature verification failed",
		},
		{
			name:      "wrong message hash",
			pubkey:    kd.SchnorrPubkey,
			message:   "0000000000000000000000000000000000000000000000000000000000000002",
			signature: sig,
			wantErr:   "signature verification failed",
		},
		{
			name:      "all zeros signature",
			pubkey:    kd.SchnorrPubkey,
			message:   message,
			signature: "0000000000000000000000000000000000000000000000000000000000000000" +
				"0000000000000000000000000000000000000000000000000000000000000000",
			wantErr: "signature verification failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifySchnorrSignature(tt.pubkey, tt.message, tt.signature)
			if err == nil {
				t.Errorf("Expected error containing %q, but got nil", tt.wantErr)
				return
			}
			if !containsSubstring(err.Error(), tt.wantErr) {
				t.Errorf("Expected error containing %q, got %q", tt.wantErr, err.Error())
			}
		})
	}
}

// flipBit flips a bit in the hex string at the given byte position (0-indexed)
func flipBit(hexStr string, bytePos int) string {
	if bytePos*2+1 >= len(hexStr) {
		return hexStr
	}
	bytes := []byte(hexStr)
	// Flip the high nibble of the byte
	if bytes[bytePos*2] >= 'a' && bytes[bytePos*2] <= 'f' {
		bytes[bytePos*2] = 'a' + (bytes[bytePos*2]-'a'+1)%6
	} else if bytes[bytePos*2] >= '0' && bytes[bytePos*2] <= '9' {
		bytes[bytePos*2] = '0' + (bytes[bytePos*2]-'0'+1)%10
	}
	return string(bytes)
}

// containsSubstring checks if s contains substr
func containsSubstring(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && len(substr) > 0 && findSubstring(s, substr)))
}

func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
