package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/google/uuid"
	"golang.org/x/crypto/sha3"
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

// JWTHeader represents the JWT header
type JWTHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// JWTPayload represents the JWT payload
type JWTPayload struct {
	Digest string `json:"digest"`
	Iss    string `json:"iss"`
	Iat    int64  `json:"iat"`
	Exp    int64  `json:"exp"`
	Jti    string `json:"jti"`
}

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

	// Parse private key
	privateKeyBytes, err := hex.DecodeString(privateKeyHex)
	if err != nil {
		fmt.Printf("Error decoding private key: %v\n", err)
		os.Exit(1)
	}

	privKey, _ := btcec.PrivKeyFromBytes(privateKeyBytes)
	pubKey := privKey.PubKey()

	// Derive Ethereum address
	address := pubKeyToAddress(pubKey.ToECDSA())
	fmt.Printf("📝 Using address: %s\n", address)

	// Build input based on operation
	input := map[string]interface{}{
		"domain": *domain,
	}

	// Add optional callback URL if provided
	if *callbackURL != "" {
		input["callback_url"] = *callbackURL
		fmt.Printf("📞 Callback URL: %s\n", *callbackURL)
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
		fmt.Printf("🔨 CREATE operation: domain=%s, thold_price=%.2f\n", *domain, priceFloat)
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
		fmt.Printf("🔍 CHECK operation: domain=%s, thold_hash=%s\n", *domain, *tholdHash)
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

	fmt.Printf("\n📦 JSON-RPC Request:\n%s\n\n", string(requestBody))

	// Compute digest
	digest := computeDigest(requestBody)
	fmt.Printf("🔐 Digest: %s\n", digest)

	// Generate JWT
	jwt, err := generateJWT(privKey.ToECDSA(), address, digest)
	if err != nil {
		fmt.Printf("Error generating JWT: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🎫 JWT: %s\n\n", jwt)

	// Send request to gateway
	fmt.Printf("🚀 Sending request to %s\n\n", GatewayURL)

	resp, err := sendRequest(GatewayURL, requestBody, jwt)
	if err != nil {
		fmt.Printf("❌ Error: %v\n", err)
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
		fmt.Printf("❌ RPC Error [%d]: %s\n", jsonResp.Error.Code, jsonResp.Error.Message)
		os.Exit(1)
	}

	fmt.Printf("✅ Success!\n\n")
	fmt.Printf("📊 Response:\n")
	prettyResp, _ := json.MarshalIndent(jsonResp, "", "  ")
	fmt.Printf("%s\n\n", string(prettyResp))

	// Extract execution ID
	if execID, ok := jsonResp.Result["workflow_execution_id"].(string); ok {
		fmt.Printf("🔗 Track execution at: https://cre.chain.link/workflows?execution=%s\n", execID)
	}
}

// marshalSorted marshals JSON with keys sorted alphabetically at all levels
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

// computeDigest computes SHA256 hash with 0x prefix
func computeDigest(data []byte) string {
	hash := sha256.Sum256(data)
	return "0x" + hex.EncodeToString(hash[:])
}

// generateJWT creates a JWT token signed with ECDSA
func generateJWT(privKey *ecdsa.PrivateKey, address, digest string) (string, error) {
	now := time.Now().Unix()

	// Create header
	header := JWTHeader{
		Alg: "ETH",
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Create payload
	payload := JWTPayload{
		Digest: digest,
		Iss:    address,
		Iat:    now,
		Exp:    now + 300, // 5 minutes
		Jti:    uuid.New().String(),
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Create message to sign
	message := headerB64 + "." + payloadB64

	// Sign with Ethereum prefix
	signature, err := signEthereumMessage(privKey, message)
	if err != nil {
		return "", err
	}

	signatureB64 := base64.RawURLEncoding.EncodeToString(signature)

	return message + "." + signatureB64, nil
}

// signEthereumMessage signs a message with Ethereum's "\x19Ethereum Signed Message:\n" prefix
func signEthereumMessage(privKey *ecdsa.PrivateKey, message string) ([]byte, error) {
	// Create Ethereum signed message prefix
	prefix := fmt.Sprintf("\x19Ethereum Signed Message:\n%d%s", len(message), message)

	// Hash with Keccak256
	hash := sha3.NewLegacyKeccak256()
	hash.Write([]byte(prefix))
	messageHash := hash.Sum(nil)

	// Convert to btcec private key for proper signing
	privKeyBytes := privKey.D.Bytes()
	if len(privKeyBytes) < 32 {
		padded := make([]byte, 32)
		copy(padded[32-len(privKeyBytes):], privKeyBytes)
		privKeyBytes = padded
	}
	btcPrivKey, btcPubKey := btcec.PrivKeyFromBytes(privKeyBytes)

	// Sign using standard ECDSA
	r, s, err := ecdsa.Sign(rand.Reader, privKey, messageHash)
	if err != nil {
		return nil, err
	}

	// Normalize s to lower value (BIP-62)
	curve := btcec.S256()
	halfOrder := new(big.Int).Rsh(curve.Params().N, 1)
	if s.Cmp(halfOrder) > 0 {
		s = new(big.Int).Sub(curve.Params().N, s)
	}

	// Pad r and s to 32 bytes
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	rPadded := make([]byte, 32)
	sPadded := make([]byte, 32)
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)

	// Compute recovery ID using proper elliptic curve recovery
	recoveryID := computeRecoveryID(btcPrivKey, btcPubKey, messageHash, r, s)

	// Format: r || s || v
	result := make([]byte, 65)
	copy(result[0:32], rPadded)
	copy(result[32:64], sPadded)
	result[64] = recoveryID

	return result, nil
}

// computeRecoveryID computes the Ethereum recovery ID (0-3)
// Panics if no valid recovery ID is found (indicates a bug in signature generation)
func computeRecoveryID(privKey *btcec.PrivateKey, pubKey *btcec.PublicKey, messageHash []byte, r, s *big.Int) byte {
	// Get uncompressed public key bytes
	pubKeyBytes := pubKey.SerializeUncompressed()
	targetX := pubKeyBytes[1:33]
	targetY := pubKeyBytes[33:65]

	// Try each recovery ID (0-3)
	for v := byte(0); v < 4; v++ {
		recovered := tryRecoverPublicKey(messageHash, r, s, v)
		if recovered != nil {
			recoveredBytes := recovered.SerializeUncompressed()
			recoveredX := recoveredBytes[1:33]
			recoveredY := recoveredBytes[33:65]

			if bytes.Equal(targetX, recoveredX) && bytes.Equal(targetY, recoveredY) {
				return v
			}
		}
	}

	// This should never happen with a valid ECDSA signature
	// Panic with diagnostic info to help debug if it does occur
	panic(fmt.Sprintf("failed to compute recovery ID: no valid recovery ID (0-3) matched for pubkey=%x, r=%x, s=%x",
		pubKeyBytes[:8], r.Bytes()[:8], s.Bytes()[:8]))
}

// tryRecoverPublicKey attempts to recover the public key from a signature
func tryRecoverPublicKey(messageHash []byte, r, s *big.Int, recoveryID byte) *btcec.PublicKey {
	curve := btcec.S256()

	// Compute R point x-coordinate
	rX := new(big.Int).Set(r)
	if recoveryID >= 2 {
		// Add N (curve order) for recovery IDs 2 and 3
		rX.Add(rX, curve.Params().N)
	}

	// Check if x is valid (must be < field prime)
	if rX.Cmp(curve.Params().P) >= 0 {
		return nil
	}

	// Compute y from x: y^2 = x^3 + 7 (secp256k1 curve equation)
	// y^2 = x^3 + ax + b, for secp256k1: a=0, b=7
	ySquared := new(big.Int).Mul(rX, rX)
	ySquared.Mul(ySquared, rX)
	ySquared.Add(ySquared, big.NewInt(7))
	ySquared.Mod(ySquared, curve.Params().P)

	// Compute y = sqrt(y^2) mod P
	y := new(big.Int).ModSqrt(ySquared, curve.Params().P)
	if y == nil {
		return nil
	}

	// Choose y based on recovery ID LSB
	if (y.Bit(0) == 1) != (recoveryID&1 == 1) {
		y.Sub(curve.Params().P, y)
	}

	// Verify point is on curve
	if !curve.IsOnCurve(rX, y) {
		return nil
	}

	// Now recover the public key Q from R point
	// Q = r^-1 * (s*R - e*G) where e is the message hash as integer

	// Compute r^-1 (modular inverse of r mod N)
	rInv := new(big.Int).ModInverse(r, curve.Params().N)
	if rInv == nil {
		return nil
	}

	// e = message hash as big int
	e := new(big.Int).SetBytes(messageHash)

	// Compute s*R
	sRx, sRy := curve.ScalarMult(rX, y, s.Bytes())

	// Compute e*G (G is the generator point)
	eGx, eGy := curve.ScalarBaseMult(e.Bytes())

	// Compute -e*G (negate y coordinate)
	negEGy := new(big.Int).Sub(curve.Params().P, eGy)

	// Compute s*R - e*G = s*R + (-e*G)
	diffX, diffY := curve.Add(sRx, sRy, eGx, negEGy)

	// Compute Q = r^-1 * (s*R - e*G)
	qX, qY := curve.ScalarMult(diffX, diffY, rInv.Bytes())

	// Verify recovered point is on curve
	if !curve.IsOnCurve(qX, qY) {
		return nil
	}

	// Create public key using btcec
	var xFieldVal, yFieldVal btcec.FieldVal
	xFieldVal.SetByteSlice(qX.Bytes())
	yFieldVal.SetByteSlice(qY.Bytes())

	pubKey := btcec.NewPublicKey(&xFieldVal, &yFieldVal)

	return pubKey
}

// pubKeyToAddress derives Ethereum address from public key
func pubKeyToAddress(pubKey *ecdsa.PublicKey) string {
	// Serialize uncompressed public key (remove 0x04 prefix)
	pubKeyBytes := append(pubKey.X.Bytes(), pubKey.Y.Bytes()...)

	// Pad to 64 bytes if needed
	if len(pubKeyBytes) < 64 {
		padded := make([]byte, 64)
		copy(padded[32-len(pubKey.X.Bytes()):32], pubKey.X.Bytes())
		copy(padded[64-len(pubKey.Y.Bytes()):64], pubKey.Y.Bytes())
		pubKeyBytes = padded
	}

	// Keccak256 hash
	hash := sha3.NewLegacyKeccak256()
	hash.Write(pubKeyBytes)
	hashBytes := hash.Sum(nil)

	// Take last 20 bytes as address
	address := hashBytes[len(hashBytes)-20:]
	return "0x" + hex.EncodeToString(address)
}

// sendRequest sends HTTP POST request with JWT authorization
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
