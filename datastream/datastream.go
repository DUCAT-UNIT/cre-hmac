// Package datastream decodes and cryptographically verifies Chainlink Data
// Streams v3 reports (BTC/USD and similar feeds).
//
// SECURITY (H1 fix): This package exists to close a money-path vulnerability in
// which the previous price decoder blindly scanned a set of byte offsets in the
// report blob and accepted the first value that "looked like" a plausible BTC
// price, WITHOUT verifying that the report was actually signed by the Chainlink
// DON. An attacker who could influence the HTTP response (or a malformed/forged
// report) could therefore inject an arbitrary price.
//
// This package replaces that with:
//
//  1. A proper Solidity-ABI decode of the outer fullReport envelope.
//  2. A proper v3 reportBlob decode that reads the price as a SIGNED int192 at
//     the exact byte offset 192 (no offset guessing).
//  3. DON signature verification: it recomputes the digest each DON signer
//     signed, recovers the signer Ethereum addresses from the report's
//     signatures, and requires at least `threshold` (f+1) DISTINCT recovered
//     addresses that are ALL members of the operator-configured authorized
//     signer set. Verification fails CLOSED.
//
// This package is intentionally pure-Go (NO //go:build wasip1 tag) so the
// crypto + decode logic is unit-testable under a normal `go test` run, mirroring
// the existing `crypto` package pattern. It is wasip1-safe: pure compute, no
// goroutines, no net, no os.
package datastream

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"math/big"
	"strings"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const (
	// wordSize is the size of a Solidity ABI word.
	wordSize = 32

	// v3PriceOffset is the byte offset of the price field inside the v3
	// reportBlob. The v3 blob layout is one 32-byte word per field:
	//   [0]   feedId               bytes32   (offset 0)
	//   [1]   validFromTimestamp   uint32    (offset 32)
	//   [2]   observationsTimestamp uint32   (offset 64)
	//   [3]   nativeFee            uint192   (offset 96)
	//   [4]   linkFee              uint192   (offset 128)
	//   [5]   expiresAt            uint32    (offset 160)
	//   [6]   price                int192    (offset 192)  <-- SIGNED
	//   [7]   bid                  int192    (offset 224)
	//   [8]   ask                  int192    (offset 256)
	v3PriceOffset = 192

	// v3MinBlobLen is the minimum length of a v3 reportBlob: 9 words. We only
	// require through the price field (offset 192 + 32 = 224) plus the optional
	// bid/ask, but we insist on at least the price word being present.
	v3MinBlobLen = v3PriceOffset + wordSize // 224
)

// keccak256 returns the Keccak-256 (legacy, pre-NIST-SHA3) digest of the
// concatenation of the provided byte slices. Ethereum / Chainlink use legacy
// Keccak, NOT FIPS-202 SHA3-256.
func keccak256(chunks ...[]byte) [32]byte {
	h := sha3.NewLegacyKeccak256()
	for _, c := range chunks {
		h.Write(c)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// DecodeFullReport decodes the outer Solidity-ABI fullReport envelope.
//
// The envelope is the ABI encoding of the tuple:
//
//	(bytes32[3] reportContext, bytes reportBlob, bytes32[] rawRs, bytes32[] rawSs, bytes32 rawVs)
//
// Standard Solidity ABI layout of the head section (5 words):
//
//	word[0..2] : reportContext[0], reportContext[1], reportContext[2] (static, inline)
//	word[3]    : offset to reportBlob (dynamic bytes)
//	word[4]    : offset to rawRs      (dynamic bytes32[])
//	word[5]    : offset to rawSs      (dynamic bytes32[])
//	word[6]    : rawVs                (static bytes32, inline; v bytes left-aligned)
//
// NOTE: reportContext is a static bytes32[3] so it occupies 3 inline words and
// rawVs is a static bytes32 occupying 1 inline word. Only reportBlob, rawRs and
// rawSs are dynamic and referenced by offset. Offsets are measured from the
// start of the tuple's data (i.e. the start of the supplied payload).
//
// vs returns one v byte per signature, in order; rawVs packs them left-aligned
// (vs[i] = rawVs word byte i). The number of v bytes returned equals len(rs).
func DecodeFullReport(payload []byte) (reportContext [3][32]byte, reportBlob []byte, rs [][32]byte, ss [][32]byte, vs []byte, err error) {
	// Head is 7 words: 3 (context) + 1 (blob offset) + 1 (rs offset) +
	// 1 (ss offset) + 1 (rawVs inline).
	const headWords = 7
	if len(payload) < headWords*wordSize {
		err = fmt.Errorf("fullReport too short: need at least %d bytes for head, got %d", headWords*wordSize, len(payload))
		return
	}

	word := func(i int) []byte { return payload[i*wordSize : (i+1)*wordSize] }

	// reportContext[0..2] are the first three inline words.
	copy(reportContext[0][:], word(0))
	copy(reportContext[1][:], word(1))
	copy(reportContext[2][:], word(2))

	// reportBlob: word[3] is an offset to (length, bytes).
	blobOff, e := readOffset(word(3), len(payload))
	if e != nil {
		err = fmt.Errorf("reportBlob offset: %w", e)
		return
	}
	reportBlob, e = readDynamicBytes(payload, blobOff)
	if e != nil {
		err = fmt.Errorf("reportBlob: %w", e)
		return
	}

	// rawRs: word[4] is an offset to a dynamic bytes32[].
	rsOff, e := readOffset(word(4), len(payload))
	if e != nil {
		err = fmt.Errorf("rawRs offset: %w", e)
		return
	}
	rs, e = readBytes32Array(payload, rsOff)
	if e != nil {
		err = fmt.Errorf("rawRs: %w", e)
		return
	}

	// rawSs: word[5] is an offset to a dynamic bytes32[].
	ssOff, e := readOffset(word(5), len(payload))
	if e != nil {
		err = fmt.Errorf("rawSs offset: %w", e)
		return
	}
	ss, e = readBytes32Array(payload, ssOff)
	if e != nil {
		err = fmt.Errorf("rawSs: %w", e)
		return
	}

	if len(rs) != len(ss) {
		err = fmt.Errorf("signature count mismatch: %d rawRs vs %d rawSs", len(rs), len(ss))
		return
	}

	// rawVs: word[6] is the inline static bytes32 packing the v values, one
	// byte each, left-aligned. We expose len(rs) of them.
	rawVs := word(6)
	if len(rs) > wordSize {
		err = fmt.Errorf("too many signatures: %d (max %d packed v bytes)", len(rs), wordSize)
		return
	}
	vs = make([]byte, len(rs))
	copy(vs, rawVs[:len(rs)])

	return
}

// readOffset interprets a 32-byte word as a non-negative ABI offset and bounds
// it against the total payload length. Offsets larger than 2^31-ish are treated
// as malformed (defensive: a real report's offsets are tiny).
func readOffset(word []byte, payloadLen int) (int, error) {
	off := new(big.Int).SetBytes(word)
	if !off.IsInt64() {
		return 0, fmt.Errorf("offset out of range")
	}
	o := off.Int64()
	if o < 0 || o > int64(payloadLen) {
		return 0, fmt.Errorf("offset %d out of bounds (payload len %d)", o, payloadLen)
	}
	return int(o), nil
}

// readDynamicBytes reads an ABI dynamic `bytes` value located at `off`: a
// 32-byte length word followed by that many bytes (right-padded to a multiple
// of 32, but we return exactly `length` bytes).
func readDynamicBytes(payload []byte, off int) ([]byte, error) {
	if off < 0 || off > len(payload)-wordSize {
		return nil, fmt.Errorf("length word out of bounds at offset %d", off)
	}
	lenBig := new(big.Int).SetBytes(payload[off : off+wordSize])
	start := off + wordSize
	maxLength := len(payload) - start
	// Compare while the attacker-controlled value is still a big.Int. Converting
	// first can wrap on wasip1/wasm32, and start+length can overflow on 64-bit.
	if lenBig.Sign() < 0 || lenBig.Cmp(big.NewInt(int64(maxLength))) > 0 {
		return nil, fmt.Errorf("bytes length out of bounds at offset %d (payload len %d)", start, len(payload))
	}
	length := int(lenBig.Int64()) // safe: 0 <= length <= maxLength (an int)
	out := make([]byte, length)
	copy(out, payload[start:start+length])
	return out, nil
}

// readBytes32Array reads an ABI dynamic `bytes32[]` located at `off`: a 32-byte
// element-count word followed by that many 32-byte elements.
func readBytes32Array(payload []byte, off int) ([][32]byte, error) {
	if off < 0 || off > len(payload)-wordSize {
		return nil, fmt.Errorf("count word out of bounds at offset %d", off)
	}
	countBig := new(big.Int).SetBytes(payload[off : off+wordSize])
	// Defensive upper bound: a report has at most ~32 signers.
	// Check before converting to int so huge values cannot wrap on wasm32.
	if countBig.Sign() < 0 || countBig.Cmp(big.NewInt(256)) > 0 {
		return nil, fmt.Errorf("implausible element count %s", countBig.String())
	}
	count := int(countBig.Int64())
	start := off + wordSize
	end := start + count*wordSize
	if end > len(payload) {
		return nil, fmt.Errorf("array out of bounds: %d elements at offset %d (payload len %d)", count, start, len(payload))
	}
	out := make([][32]byte, count)
	for i := range count {
		copy(out[i][:], payload[start+i*wordSize:start+(i+1)*wordSize])
	}
	return out, nil
}

// DecodeV3Price decodes a Chainlink v3 reportBlob and returns the feedId, the
// signed price (read as int192 at byte offset 192), and the observations
// timestamp. The price is the raw on-chain integer with the feed's 18 implied
// decimals; callers scale by 1e18 to obtain a human price.
//
// SECURITY: The price is read at the EXACT offset 192 as a SIGNED two's
// complement int192. This replaces the previous brute-force offset scan that
// could latch onto an attacker-controlled or garbage value.
func DecodeV3Price(reportBlob []byte) (feedID [32]byte, price *big.Int, observationsTimestamp uint32, err error) {
	if len(reportBlob) < v3MinBlobLen {
		err = fmt.Errorf("reportBlob too short for v3 decode: need at least %d bytes, got %d", v3MinBlobLen, len(reportBlob))
		return
	}

	// feedId is word[0].
	copy(feedID[:], reportBlob[0:wordSize])

	// observationsTimestamp is word[2] (uint32 right-aligned in the 32-byte
	// word). Read the low 4 bytes.
	otWord := reportBlob[2*wordSize : 3*wordSize]
	observationsTimestamp = uint32(otWord[28])<<24 | uint32(otWord[29])<<16 | uint32(otWord[30])<<8 | uint32(otWord[31])

	// price is word[6] at byte offset 192, a SIGNED int192. The int192 occupies
	// the low 24 bytes of the word; the high 8 bytes are sign extension (0x00
	// for positive, 0xFF for negative) for a well-formed report.
	priceWord := reportBlob[v3PriceOffset : v3PriceOffset+wordSize]
	price = decodeInt192(priceWord)

	return
}

// decodeInt192 decodes a SIGNED two's complement int192 from a 32-byte ABI
// word. An int192 is sign-extended to fill the full 32-byte word, so the sign
// is the top bit of the whole word. We interpret the entire 32-byte word as a
// signed 256-bit value, which yields the correct int192 value because the
// upper 8 bytes are the sign extension of the int192.
func decodeInt192(word []byte) *big.Int {
	v := new(big.Int).SetBytes(word) // unsigned interpretation of 32 bytes
	// If the top bit of the 256-bit word is set, it is negative: subtract 2^256.
	if word[0]&0x80 != 0 {
		twoTo256 := new(big.Int).Lsh(big.NewInt(1), 256)
		v.Sub(v, twoTo256)
	}
	return v
}

// recoverSigner recovers the Ethereum address (20 bytes) of the signer for a
// single signature over digest h, given the 32-byte r, 32-byte s and the
// recovery id v (0 or 1; if a caller passes the 27/28 form it is normalized).
//
// The decred RecoverCompact expects a 65-byte compact signature laid out as
// [recoveryCode(=27+recID)][R(32)][S(32)] and returns the uncompressed public
// key. The Ethereum address is the last 20 bytes of keccak256 of the 64-byte
// uncompressed public key (X||Y), i.e. of SerializeUncompressed()[1:].
func recoverSigner(h [32]byte, r, s [32]byte, v byte) ([20]byte, error) {
	var addr [20]byte

	// Normalize v to a recovery id in {0,1}.
	recID := v
	if recID >= 27 {
		recID -= 27
	}
	if recID != 0 && recID != 1 {
		return addr, fmt.Errorf("invalid recovery id %d", v)
	}

	var compact [65]byte
	compact[0] = 27 + recID // decred's compactSigMagicOffset is 27
	copy(compact[1:33], r[:])
	copy(compact[33:65], s[:])

	pub, _, err := ecdsa.RecoverCompact(compact[:], h[:])
	if err != nil {
		return addr, fmt.Errorf("recover failed: %w", err)
	}

	uncompressed := pub.SerializeUncompressed() // 0x04 || X(32) || Y(32)
	if len(uncompressed) != 65 {
		return addr, fmt.Errorf("unexpected uncompressed pubkey length %d", len(uncompressed))
	}
	hash := keccak256(uncompressed[1:]) // hash of X||Y
	copy(addr[:], hash[12:])            // last 20 bytes
	return addr, nil
}

// ComputeReportDigest computes the digest each DON signer signed:
//
//	h = keccak256( keccak256(reportBlob) || ctx0 || ctx1 || ctx2 )
//
// i.e. abi.encodePacked of the 32-byte report hash followed by the three
// 32-byte reportContext words.
func ComputeReportDigest(reportContext [3][32]byte, reportBlob []byte) [32]byte {
	blobHash := keccak256(reportBlob)
	return keccak256(blobHash[:], reportContext[0][:], reportContext[1][:], reportContext[2][:])
}

// VerifyReportSigners verifies that a Chainlink Data Streams report was signed
// by an acceptable quorum of authorized DON signers.
//
// It:
//  1. Computes the signed digest h.
//  2. Recovers the signer address for each (rs[i], ss[i], vs[i]) over h.
//  3. Requires at least `threshold` DISTINCT recovered addresses, ALL of which
//     are members of `authorizedSigners`.
//
// It FAILS CLOSED: any malformed input, a recovery failure, a recovered signer
// that is NOT in the authorized set, or fewer than `threshold` distinct
// authorized signers, all produce a non-nil error.
//
// `authorizedSigners` is keyed by 20-byte Ethereum address; `threshold` is the
// f+1 minimum number of distinct authorized signers required.
func VerifyReportSigners(reportContext [3][32]byte, reportBlob []byte, rs, ss [][32]byte, vs []byte, authorizedSigners map[[20]byte]bool, threshold int) error {
	if threshold < 1 {
		return fmt.Errorf("threshold must be >= 1, got %d", threshold)
	}
	if len(authorizedSigners) == 0 {
		return fmt.Errorf("no authorized signers configured")
	}
	if len(rs) != len(ss) || len(rs) != len(vs) {
		return fmt.Errorf("signature component length mismatch: %d rs, %d ss, %d vs", len(rs), len(ss), len(vs))
	}
	if len(rs) < threshold {
		return fmt.Errorf("not enough signatures: have %d, need at least %d", len(rs), threshold)
	}

	h := ComputeReportDigest(reportContext, reportBlob)

	seen := make(map[[20]byte]bool, len(rs))
	for i := range rs {
		addr, err := recoverSigner(h, rs[i], ss[i], vs[i])
		if err != nil {
			// Fail closed: a recovery failure on a money-path report is fatal.
			return fmt.Errorf("signature %d recovery failed: %w", i, err)
		}
		if !authorizedSigners[addr] {
			// Fail closed: ANY recovered signer outside the authorized set
			// rejects the whole report.
			return fmt.Errorf("signature %d recovered unauthorized signer 0x%x", i, addr)
		}
		seen[addr] = true
	}

	if len(seen) < threshold {
		return fmt.Errorf("insufficient distinct authorized signers: got %d, need %d", len(seen), threshold)
	}

	return nil
}

// RecoverReportSigners recovers and returns ALL signer Ethereum addresses
// (20 bytes each) for a Chainlink Data Streams report, in signature order.
//
// Unlike VerifyReportSigners, this performs NO authorization check: it does not
// require the recovered addresses to be in any configured set and it does not
// enforce a threshold. It exists for DISCOVERY/diagnostics — e.g. a tester that
// fetches a real report and wants to print the actual DON signer addresses so an
// operator can compare them against the on-chain Verifier signer configuration.
//
// It recomputes the same digest the DON signed (via ComputeReportDigest) and
// runs the same recovery as VerifyReportSigners (recoverSigner). It returns an
// error on a component-length mismatch or on the FIRST recovery failure, so a
// malformed report is surfaced loudly rather than silently dropping signatures.
//
// SECURITY: This helper does NOT verify the report. Callers MUST NOT trust a
// price just because RecoverReportSigners succeeded; use VerifyReportSigners for
// the money path. Pure/wasip1-safe: no goroutines, no net, no os.
func RecoverReportSigners(reportContext [3][32]byte, reportBlob []byte, rs, ss [][32]byte, vs []byte) ([][20]byte, error) {
	if len(rs) != len(ss) || len(rs) != len(vs) {
		return nil, fmt.Errorf("signature component length mismatch: %d rs, %d ss, %d vs", len(rs), len(ss), len(vs))
	}

	h := ComputeReportDigest(reportContext, reportBlob)

	addrs := make([][20]byte, 0, len(rs))
	for i := range rs {
		addr, err := recoverSigner(h, rs[i], ss[i], vs[i])
		if err != nil {
			return nil, fmt.Errorf("signature %d recovery failed: %w", i, err)
		}
		addrs = append(addrs, addr)
	}
	return addrs, nil
}

// ParseSignerAddress parses a lowercased/any-case 0x-prefixed 20-byte hex
// Ethereum address into a [20]byte. It is tolerant of an optional 0x prefix and
// mixed case, but strict on length.
func ParseSignerAddress(s string) ([20]byte, error) {
	var addr [20]byte
	clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(s), "0x"), "0X")
	if len(clean) != 40 {
		return addr, fmt.Errorf("invalid signer address length: expected 40 hex chars, got %d (%q)", len(clean), s)
	}
	b, err := hex.DecodeString(clean)
	if err != nil {
		return addr, fmt.Errorf("invalid signer address hex %q: %w", s, err)
	}
	copy(addr[:], b)
	return addr, nil
}

// BuildAuthorizedSignerSet parses a slice of hex address strings into a set
// suitable for VerifyReportSigners. Duplicate addresses collapse to one entry.
func BuildAuthorizedSignerSet(addrs []string) (map[[20]byte]bool, error) {
	set := make(map[[20]byte]bool, len(addrs))
	for _, a := range addrs {
		addr, err := ParseSignerAddress(a)
		if err != nil {
			return nil, err
		}
		set[addr] = true
	}
	return set, nil
}

// FeedIDMatches reports whether the decoded feedID (32 bytes) equals the
// operator-configured feed id string (with optional 0x prefix, any case). It
// returns false on any parse mismatch.
func FeedIDMatches(decoded [32]byte, configured string) bool {
	clean := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(configured), "0x"), "0X")
	want, err := hex.DecodeString(clean)
	if err != nil || len(want) != 32 {
		return false
	}
	return bytes.Equal(decoded[:], want)
}
