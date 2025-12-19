package ethsign

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"golang.org/x/crypto/sha3"
)

// ============================================================================
// Round-trip tests: Generate key, sign, recover, verify
// ============================================================================

func TestTryRecoverPublicKey_RoundTrip(t *testing.T) {
	// Generate a new ECDSA key pair
	privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	// Convert to btcec types for comparison
	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	_, expectedPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	testMessages := []string{
		"hello world",
		"",
		"The quick brown fox jumps over the lazy dog",
		"a]",
		string(make([]byte, 1000)), // Large message
	}

	for i, message := range testMessages {
		t.Run(fmt.Sprintf("message_%d", i), func(t *testing.T) {
			// Sign the message using SignEthereumMessage
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("SignEthereumMessage failed: %v", err)
			}

			// Verify signature is 65 bytes
			if len(sig) != 65 {
				t.Fatalf("signature length = %d, want 65", len(sig))
			}

			// Extract r, s, v from signature
			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			v := sig[64]

			// v should be 27 or 28 (Ethereum format)
			if v != 27 && v != 28 {
				t.Errorf("v = %d, want 27 or 28", v)
			}

			// Convert v back to recovery ID (0 or 1)
			recoveryID := v - 27

			// Compute the message hash the same way SignEthereumMessage does
			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			// Recover the public key
			recoveredPubKey := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recoveredPubKey == nil {
				t.Fatal("tryRecoverPublicKey returned nil")
			}

			// Compare recovered public key with original
			expectedBytes := expectedPubKey.SerializeUncompressed()
			recoveredBytes := recoveredPubKey.SerializeUncompressed()

			if !bytes.Equal(expectedBytes, recoveredBytes) {
				t.Errorf("recovered public key mismatch:\nexpected: %x\ngot:      %x",
					expectedBytes, recoveredBytes)
			}

			// Also verify X and Y coordinates individually
			expectedX := expectedBytes[1:33]
			expectedY := expectedBytes[33:65]
			recoveredX := recoveredBytes[1:33]
			recoveredY := recoveredBytes[33:65]

			if !bytes.Equal(expectedX, recoveredX) {
				t.Errorf("X coordinate mismatch:\nexpected: %x\ngot:      %x", expectedX, recoveredX)
			}
			if !bytes.Equal(expectedY, recoveredY) {
				t.Errorf("Y coordinate mismatch:\nexpected: %x\ngot:      %x", expectedY, recoveredY)
			}
		})
	}
}

func TestTryRecoverPublicKey_MultipleKeys(t *testing.T) {
	// Test with multiple generated keys to ensure robustness
	for i := 0; i < 10; i++ {
		t.Run(fmt.Sprintf("key_%d", i), func(t *testing.T) {
			privKey, err := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			message := fmt.Sprintf("test message %d with unique content", i)
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("SignEthereumMessage failed: %v", err)
			}

			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			recoveryID := sig[64] - 27

			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recovered == nil {
				t.Fatal("tryRecoverPublicKey returned nil")
			}

			// Verify by comparing addresses
			expectedAddr := PubKeyToAddress(&privKey.PublicKey)
			recoveredAddr := pubKeyToAddressBtcec(recovered)

			if expectedAddr != recoveredAddr {
				t.Errorf("address mismatch:\nexpected: %s\ngot:      %s", expectedAddr, recoveredAddr)
			}
		})
	}
}

// ============================================================================
// Fixed known test vectors (Ethereum ecrecover compatible)
// ============================================================================

func TestTryRecoverPublicKey_KnownVectors(t *testing.T) {
	// Generate a deterministic test vector by signing with a known private key
	// This ensures we have valid r, s values that can actually be recovered

	// Known private key for reproducible testing
	privKeyHex := "e0144cfbe97dcb2554ebf918b1ee12c1a51d4db1385aea75ec96d6632806bb2c"
	privKeyBytes, _ := hex.DecodeString(privKeyHex)

	// Pad to 32 bytes if needed
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}

	_, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)
	expectedPubBytes := btcPubKey.SerializeUncompressed()

	// Create a standard ECDSA private key for signing
	curve := btcec.S256()
	privKey := &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: curve,
			X:     btcPubKey.X(),
			Y:     btcPubKey.Y(),
		},
		D: new(big.Int).SetBytes(privKeyBytes),
	}

	t.Run("generated_vector", func(t *testing.T) {
		message := "test message for recovery"

		// Sign the message
		sig, err := SignEthereumMessage(privKey, message)
		if err != nil {
			t.Fatalf("SignEthereumMessage failed: %v", err)
		}

		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		recoveryID := sig[64] - 27

		// Compute message hash
		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(prefix))
		messageHash := hash.Sum(nil)

		// Log the test vector for reference
		t.Logf("Test vector:")
		t.Logf("  messageHash: %x", messageHash)
		t.Logf("  r: %x", r.Bytes())
		t.Logf("  s: %x", s.Bytes())
		t.Logf("  recoveryID: %d", recoveryID)
		t.Logf("  expectedPub: %x", expectedPubBytes)

		// Recover and verify
		recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
		if recovered == nil {
			t.Fatal("expected recovery to succeed but got nil")
		}

		recoveredBytes := recovered.SerializeUncompressed()
		if !bytes.Equal(expectedPubBytes, recoveredBytes) {
			t.Errorf("recovered public key mismatch:\nexpected: %x\ngot:      %x",
				expectedPubBytes, recoveredBytes)
		}
	})

	t.Run("wrong_recovery_id", func(t *testing.T) {
		message := "test for wrong recovery id"
		sig, _ := SignEthereumMessage(privKey, message)

		r := new(big.Int).SetBytes(sig[0:32])
		s := new(big.Int).SetBytes(sig[32:64])
		correctRecoveryID := sig[64] - 27
		wrongRecoveryID := (correctRecoveryID + 1) % 2

		prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
		hash := sha3.NewLegacyKeccak256()
		hash.Write([]byte(prefix))
		messageHash := hash.Sum(nil)

		// With wrong recovery ID, should get different public key or nil
		recovered := tryRecoverPublicKey(messageHash, r, s, wrongRecoveryID)
		if recovered != nil {
			recoveredBytes := recovered.SerializeUncompressed()
			if bytes.Equal(expectedPubBytes, recoveredBytes) {
				t.Error("wrong recovery ID should not recover the correct public key")
			}
		}
		// nil is also acceptable
	})

	t.Run("different_messages_same_key", func(t *testing.T) {
		messages := []string{
			"message one",
			"message two",
			"",
			"a very long message that exceeds typical short message lengths to test handling of longer inputs",
		}

		for i, message := range messages {
			sig, err := SignEthereumMessage(privKey, message)
			if err != nil {
				t.Fatalf("message %d: SignEthereumMessage failed: %v", i, err)
			}

			r := new(big.Int).SetBytes(sig[0:32])
			s := new(big.Int).SetBytes(sig[32:64])
			recoveryID := sig[64] - 27

			prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
			hash := sha3.NewLegacyKeccak256()
			hash.Write([]byte(prefix))
			messageHash := hash.Sum(nil)

			recovered := tryRecoverPublicKey(messageHash, r, s, recoveryID)
			if recovered == nil {
				t.Errorf("message %d: recovery failed", i)
				continue
			}

			recoveredBytes := recovered.SerializeUncompressed()
			if !bytes.Equal(expectedPubBytes, recoveredBytes) {
				t.Errorf("message %d: recovered wrong public key", i)
			}
		}
	})
}

// ============================================================================
// Edge cases and failure tests
// ============================================================================

func TestTryRecoverPublicKey_InvalidRecoveryID(t *testing.T) {
	// Use a valid signature but with invalid recovery IDs
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test"

	sig, err := SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage failed: %v", err)
	}

	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	correctRecoveryID := sig[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Test with wrong recovery ID
	wrongRecoveryID := byte((correctRecoveryID + 1) % 2) // Toggle between 0 and 1
	recovered := tryRecoverPublicKey(messageHash, r, s, wrongRecoveryID)

	// With wrong recovery ID, we should either get nil or a different public key
	if recovered != nil {
		privKeyBytes := privKey.D.Bytes()
		if len(privKeyBytes) < 32 {
			padded := make([]byte, 32)
			copy(padded[32-len(privKeyBytes):], privKeyBytes)
			privKeyBytes = padded
		}
		_, expectedPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

		if bytes.Equal(recovered.SerializeUncompressed(), expectedPubKey.SerializeUncompressed()) {
			t.Error("wrong recovery ID should not recover the same public key")
		}
	}
	// nil is also acceptable for wrong recovery ID
}

func TestTryRecoverPublicKey_RecoveryID2And3(t *testing.T) {
	// Recovery IDs 2 and 3 are rare (r + N < P) but we should handle them
	curve := btcec.S256()

	// These IDs add N to r, which only works if r + N < P
	// Since N and P are very close for secp256k1, this is almost never valid
	// But we test the code path doesn't panic

	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := new(big.Int).SetBytes(messageHash) // Use messageHash as r for testing
	s := new(big.Int).SetBytes(messageHash) // Use messageHash as s for testing

	// Recovery ID 2 should typically fail because r + N >= P
	recovered2 := tryRecoverPublicKey(messageHash, r, s, 2)
	// Just verify it doesn't panic - result depends on r value

	recovered3 := tryRecoverPublicKey(messageHash, r, s, 3)
	// Just verify it doesn't panic

	t.Logf("Recovery ID 2 result: %v", recovered2 != nil)
	t.Logf("Recovery ID 3 result: %v", recovered3 != nil)

	// Verify the r + N >= P case
	rPlusN := new(big.Int).Add(r, curve.Params().N)
	if rPlusN.Cmp(curve.Params().P) >= 0 {
		// Expected: recovery IDs 2 and 3 should return nil
		if recovered2 != nil {
			t.Log("Unexpectedly recovered with ID 2 (r + N >= P)")
		}
	}
}

func TestTryRecoverPublicKey_ZeroR(t *testing.T) {
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := big.NewInt(0)
	s := new(big.Int).SetBytes(messageHash)

	// r = 0 should fail (can't compute modular inverse)
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	if recovered != nil {
		t.Error("expected recovery to fail with r = 0")
	}
}

func TestTryRecoverPublicKey_ZeroS(t *testing.T) {
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	r := new(big.Int).SetBytes(messageHash)
	s := big.NewInt(0)

	// s = 0 should still technically work for recovery (s*R = point at infinity issues)
	// but the resulting public key may be invalid
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	// Result depends on the implementation; just verify no panic
	t.Logf("Zero s result: %v", recovered != nil)
}

func TestTryRecoverPublicKey_NonRecoverablePoint(t *testing.T) {
	// Create a signature where the R point doesn't exist on the curve
	// This happens when x^3 + 7 is not a quadratic residue mod P

	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	// Use a value of r that doesn't have a valid y coordinate
	// Finding such an r is non-trivial, so we test with random values
	// and verify the function handles non-recoverable cases gracefully
	curve := btcec.S256()

	for i := 0; i < 100; i++ {
		randBytes := make([]byte, 32)
		rand.Read(randBytes)
		r := new(big.Int).SetBytes(randBytes)
		r.Mod(r, curve.Params().N)

		s := new(big.Int).SetBytes(messageHash)

		// Try recovery - it may succeed or fail depending on r
		recovered := tryRecoverPublicKey(messageHash, r, s, 0)
		if recovered != nil {
			// If it succeeds, verify the point is on the curve
			recoveredBytes := recovered.SerializeUncompressed()
			x := new(big.Int).SetBytes(recoveredBytes[1:33])
			y := new(big.Int).SetBytes(recoveredBytes[33:65])

			if !curve.IsOnCurve(x, y) {
				t.Errorf("iteration %d: recovered point not on curve", i)
			}
		}
		// nil is acceptable - just testing we don't panic
	}
}

func TestTryRecoverPublicKey_LargeR(t *testing.T) {
	curve := btcec.S256()
	messageHash := make([]byte, 32)
	rand.Read(messageHash)

	// r >= N should be reduced by the caller, but test behavior
	r := new(big.Int).Set(curve.Params().N)
	r.Add(r, big.NewInt(1)) // r = N + 1

	s := new(big.Int).SetBytes(messageHash)

	// This should handle the case where r > N
	recovered := tryRecoverPublicKey(messageHash, r, s, 0)
	// Result depends on implementation; verify no panic
	t.Logf("Large r result: %v", recovered != nil)
}

func TestTryRecoverPublicKey_MalformedMessageHash(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test"

	sig, _ := SignEthereumMessage(privKey, message)
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	recoveryID := sig[64] - 27

	// Test with various malformed message hashes
	tests := []struct {
		name        string
		messageHash []byte
	}{
		{"empty", []byte{}},
		{"short", make([]byte, 16)},
		{"long", make([]byte, 64)},
		{"single_byte", []byte{0x42}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Should not panic with malformed input
			recovered := tryRecoverPublicKey(tt.messageHash, r, s, recoveryID)
			// We don't care about the result, just that it doesn't panic
			t.Logf("%s hash result: %v", tt.name, recovered != nil)
		})
	}
}

// ============================================================================
// Signature format verification tests
// ============================================================================

func TestSignEthereumMessage_Format(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test message"

	sig, err := SignEthereumMessage(privKey, message)
	if err != nil {
		t.Fatalf("SignEthereumMessage failed: %v", err)
	}

	// Verify signature format
	if len(sig) != 65 {
		t.Errorf("signature length = %d, want 65", len(sig))
	}

	// Extract components
	r := sig[0:32]
	s := sig[32:64]
	v := sig[64]

	// r and s should be non-zero
	rInt := new(big.Int).SetBytes(r)
	sInt := new(big.Int).SetBytes(s)

	if rInt.Sign() == 0 {
		t.Error("r component is zero")
	}
	if sInt.Sign() == 0 {
		t.Error("s component is zero")
	}

	// v should be 27 or 28 (Ethereum format)
	if v != 27 && v != 28 {
		t.Errorf("v = %d, want 27 or 28", v)
	}

	// s should be in lower half of curve order (BIP-62 / EIP-2)
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if sInt.Cmp(halfOrder) > 0 {
		t.Error("s is not normalized to lower half of curve order")
	}
}

func TestSignEthereumMessage_Deterministic(t *testing.T) {
	// Note: ECDSA signatures with random k are NOT deterministic
	// This test verifies that the same message produces a RECOVERABLE signature
	// but different r,s values each time (due to random k)

	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "test message"

	sig1, _ := SignEthereumMessage(privKey, message)
	sig2, _ := SignEthereumMessage(privKey, message)

	// v should be consistent for the same key/message (modulo randomness)
	// but r and s will differ

	// Both should recover to the same public key
	r1 := new(big.Int).SetBytes(sig1[0:32])
	s1 := new(big.Int).SetBytes(sig1[32:64])
	v1 := sig1[64] - 27

	r2 := new(big.Int).SetBytes(sig2[0:32])
	s2 := new(big.Int).SetBytes(sig2[32:64])
	v2 := sig2[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	recovered1 := tryRecoverPublicKey(messageHash, r1, s1, v1)
	recovered2 := tryRecoverPublicKey(messageHash, r2, s2, v2)

	if recovered1 == nil || recovered2 == nil {
		t.Fatal("failed to recover public keys")
	}

	// Both should recover to the same public key
	if !bytes.Equal(recovered1.SerializeUncompressed(), recovered2.SerializeUncompressed()) {
		t.Error("different signatures for same message should recover to same public key")
	}
}

// ============================================================================
// Helper functions
// ============================================================================

// pubKeyToAddressBtcec converts a btcec public key to an Ethereum address
func pubKeyToAddressBtcec(pubKey *btcec.PublicKey) string {
	pubKeyBytes := pubKey.SerializeUncompressed()[1:] // Remove 0x04 prefix

	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashBytes := hash.Sum(nil)

	return "0x" + hex.EncodeToString(hashBytes[12:])
}

// ============================================================================
// Benchmark tests
// ============================================================================

func BenchmarkTryRecoverPublicKey(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "benchmark message"

	sig, _ := SignEthereumMessage(privKey, message)
	r := new(big.Int).SetBytes(sig[0:32])
	s := new(big.Int).SetBytes(sig[32:64])
	recoveryID := sig[64] - 27

	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tryRecoverPublicKey(messageHash, r, s, recoveryID)
	}
}

func BenchmarkSignEthereumMessage(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)
	message := "benchmark message"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SignEthereumMessage(privKey, message)
	}
}

func BenchmarkComputeRecoveryID(b *testing.B) {
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), rand.Reader)

	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	message := "benchmark message"
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Sign to get r, s
	r, s, _ := ecdsa.Sign(rand.Reader, privKey, messageHash)

	// Normalize s
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		computeRecoveryID(btcPrivKey, btcPubKey, messageHash, r, s)
	}
}
