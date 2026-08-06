package datastream

import (
	"bytes"
	"math/big"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

// --- synthetic report construction helpers ------------------------------------

// padLeft32 right-aligns b into a 32-byte word (big-endian numeric layout).
func padLeft32(b []byte) [32]byte {
	var w [32]byte
	copy(w[32-len(b):], b)
	return w
}

// uint32Word encodes a uint32 right-aligned in a 32-byte word.
func uint32Word(v uint32) [32]byte {
	return padLeft32([]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// int192Word encodes a signed integer as an int192 sign-extended into a full
// 32-byte ABI word (matches how Solidity ABI-encodes int192).
func int192Word(v *big.Int) [32]byte {
	var w [32]byte
	if v.Sign() >= 0 {
		b := v.Bytes()
		copy(w[32-len(b):], b)
		return w
	}
	// two's complement over 256 bits, which sign-extends the int192 correctly.
	mod := new(big.Int).Lsh(big.NewInt(1), 256)
	tc := new(big.Int).Add(mod, v) // 2^256 + v  (v negative)
	b := tc.Bytes()
	copy(w[32-len(b):], b)
	return w
}

// buildV3Blob builds a minimal 9-word v3 reportBlob with the given feedID,
// observationsTimestamp and signed price.
func buildV3Blob(feedID [32]byte, obsTs uint32, price *big.Int) []byte {
	blob := make([]byte, 9*wordSize)
	copy(blob[0:32], feedID[:]) // [0] feedId
	w := uint32Word(1000)       // [1] validFromTimestamp
	copy(blob[32:64], w[:])
	w = uint32Word(obsTs) // [2] observationsTimestamp
	copy(blob[64:96], w[:])
	// [3] nativeFee, [4] linkFee left zero
	w = uint32Word(2000) // [5] expiresAt
	copy(blob[160:192], w[:])
	pw := int192Word(price) // [6] price at offset 192
	copy(blob[192:224], pw[:])
	// [7] bid, [8] ask left zero
	return blob
}

// encodeFullReport ABI-encodes the outer envelope tuple:
//
//	(bytes32[3] reportContext, bytes reportBlob, bytes32[] rawRs, bytes32[] rawSs, bytes32 rawVs)
func encodeFullReport(ctx [3][32]byte, blob []byte, rs, ss [][32]byte, vs []byte) []byte {
	const headWords = 7
	head := make([]byte, headWords*wordSize)

	// reportContext[0..2] inline.
	copy(head[0:32], ctx[0][:])
	copy(head[32:64], ctx[1][:])
	copy(head[64:96], ctx[2][:])

	var tail []byte
	tailBase := headWords * wordSize

	// reportBlob offset (word[3]) -> dynamic bytes section.
	blobOff := tailBase + len(tail)
	putUintWord(head[96:128], uint64(blobOff))
	tail = append(tail, encodeDynamicBytes(blob)...)

	// rawRs offset (word[4]).
	rsOff := tailBase + len(tail)
	putUintWord(head[128:160], uint64(rsOff))
	tail = append(tail, encodeBytes32Array(rs)...)

	// rawSs offset (word[5]).
	ssOff := tailBase + len(tail)
	putUintWord(head[160:192], uint64(ssOff))
	tail = append(tail, encodeBytes32Array(ss)...)

	// rawVs inline (word[6]): v bytes left-aligned.
	var vsWord [32]byte
	copy(vsWord[:], vs)
	copy(head[192:224], vsWord[:])

	return append(head, tail...)
}

func putUintWord(dst []byte, v uint64) {
	var w [32]byte
	for i := range 8 {
		w[31-i] = byte(v >> (8 * i))
	}
	copy(dst, w[:])
}

func encodeDynamicBytes(b []byte) []byte {
	out := make([]byte, 0, 32+((len(b)+31)/32)*32)
	var lenWord [32]byte
	putUintWord(lenWord[:], uint64(len(b)))
	out = append(out, lenWord[:]...)
	out = append(out, b...)
	if pad := (32 - len(b)%32) % 32; pad > 0 {
		out = append(out, make([]byte, pad)...)
	}
	return out
}

func encodeBytes32Array(arr [][32]byte) []byte {
	out := make([]byte, 0, 32+len(arr)*32)
	var countWord [32]byte
	putUintWord(countWord[:], uint64(len(arr)))
	out = append(out, countWord[:]...)
	for _, e := range arr {
		out = append(out, e[:]...)
	}
	return out
}

// signDigest signs digest h with key and returns (r, s, v) where v is the
// recovery id in {0,1}. It uses decred SignCompact and re-derives the recovery
// id from the compact recovery code.
func signDigest(t *testing.T, key *secp256k1.PrivateKey, h [32]byte) ([32]byte, [32]byte, byte) {
	t.Helper()
	compact := ecdsa.SignCompact(key, h[:], false) // [recCode][R(32)][S(32)]
	if len(compact) != 65 {
		t.Fatalf("unexpected compact sig length %d", len(compact))
	}
	recCode := compact[0]
	// decred uses 27 + recID (+4 if compressed; we passed false).
	v := recCode - 27
	var r, s [32]byte
	copy(r[:], compact[1:33])
	copy(s[:], compact[33:65])
	return r, s, v
}

func ethAddrOf(key *secp256k1.PrivateKey) [20]byte {
	pub := key.PubKey().SerializeUncompressed()
	hh := sha3.NewLegacyKeccak256()
	hh.Write(pub[1:])
	sum := hh.Sum(nil)
	var addr [20]byte
	copy(addr[:], sum[12:])
	return addr
}

// --- test fixture --------------------------------------------------------------

type fixture struct {
	ctx       [3][32]byte
	blob      []byte
	rs        [][32]byte
	ss        [][32]byte
	vs        []byte
	signers   []*secp256k1.PrivateKey
	addrs     [][20]byte
	feedID    [32]byte
	price     *big.Int
	fullBytes []byte
}

func newFixture(t *testing.T, numSigners int, price *big.Int) *fixture {
	t.Helper()

	// deterministic feedID & context.
	var feedID [32]byte
	feedID[0] = 0x00
	feedID[1] = 0x03 // v3-ish report type prefix; value is arbitrary for tests
	for i := range feedID {
		if i >= 2 {
			feedID[i] = byte(i)
		}
	}

	var ctx [3][32]byte
	for i := range ctx {
		for j := range ctx[i] {
			ctx[i][j] = byte((i+1)*16 + j%16)
		}
	}

	blob := buildV3Blob(feedID, 1_700_000_000, price)
	digest := ComputeReportDigest(ctx, blob)

	var rs, ss [][32]byte
	var vs []byte
	var keys []*secp256k1.PrivateKey
	var addrs [][20]byte
	for range numSigners {
		k, err := secp256k1.GeneratePrivateKey()
		if err != nil {
			t.Fatalf("keygen: %v", err)
		}
		r, s, v := signDigest(t, k, digest)
		rs = append(rs, r)
		ss = append(ss, s)
		vs = append(vs, v)
		keys = append(keys, k)
		addrs = append(addrs, ethAddrOf(k))
	}

	full := encodeFullReport(ctx, blob, rs, ss, vs)

	return &fixture{
		ctx: ctx, blob: blob, rs: rs, ss: ss, vs: vs,
		signers: keys, addrs: addrs, feedID: feedID, price: price, fullBytes: full,
	}
}

func signerSet(addrs [][20]byte) map[[20]byte]bool {
	set := make(map[[20]byte]bool, len(addrs))
	for _, a := range addrs {
		set[a] = true
	}
	return set
}

// --- tests ---------------------------------------------------------------------

// (i) correct price decoded at offset 192, and round-trips through the outer
// envelope decode.
func TestDecode_PriceAtOffset192(t *testing.T) {
	// 64,234.12 BTC/USD * 1e18
	want := new(big.Int)
	want.SetString("64234120000000000000000", 10)
	f := newFixture(t, 4, want)

	ctx, blob, rs, ss, vs, err := DecodeFullReport(f.fullBytes)
	if err != nil {
		t.Fatalf("DecodeFullReport: %v", err)
	}
	if ctx != f.ctx {
		t.Fatalf("reportContext mismatch")
	}
	if !bytes.Equal(blob, f.blob) {
		t.Fatalf("reportBlob mismatch")
	}
	if len(rs) != 4 || len(ss) != 4 || len(vs) != 4 {
		t.Fatalf("signature counts wrong: rs=%d ss=%d vs=%d", len(rs), len(ss), len(vs))
	}

	feedID, price, obsTs, err := DecodeV3Price(blob)
	if err != nil {
		t.Fatalf("DecodeV3Price: %v", err)
	}
	if feedID != f.feedID {
		t.Fatalf("feedID mismatch")
	}
	if price.Cmp(want) != 0 {
		t.Fatalf("price mismatch: got %s want %s", price.String(), want.String())
	}
	if obsTs != 1_700_000_000 {
		t.Fatalf("obsTs mismatch: got %d", obsTs)
	}
}

// negative price decodes correctly as a signed int192.
func TestDecode_NegativePriceSigned(t *testing.T) {
	want := big.NewInt(-12345)
	f := newFixture(t, 1, want)
	_, price, _, err := DecodeV3Price(f.blob)
	if err != nil {
		t.Fatalf("DecodeV3Price: %v", err)
	}
	if price.Cmp(want) != 0 {
		t.Fatalf("signed price mismatch: got %s want %s", price.String(), want.String())
	}
}

func TestDecodeFullReport_RejectsHugeDynamicLengthsWithoutPanic(t *testing.T) {
	f := newFixture(t, 1, big.NewInt(1))

	tests := []struct {
		name       string
		offsetWord int
		value      *big.Int
	}{
		{"blob length max int64", 3, new(big.Int).SetUint64(^uint64(0) >> 1)},
		{"blob length wasm32 overflow", 3, new(big.Int).Lsh(big.NewInt(1), 32)},
		{"signature count wasm32 overflow", 4, new(big.Int).Lsh(big.NewInt(1), 32)},
		{"signature count max int64", 5, new(big.Int).SetUint64(^uint64(0) >> 1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			payload := append([]byte(nil), f.fullBytes...)
			off := int(new(big.Int).SetBytes(payload[tt.offsetWord*wordSize : (tt.offsetWord+1)*wordSize]).Int64())
			word := padLeft32(tt.value.Bytes())
			copy(payload[off:off+wordSize], word[:])

			if _, _, _, _, _, err := DecodeFullReport(payload); err == nil {
				t.Fatal("expected oversized ABI length/count to be rejected")
			}
		})
	}
}

// (ii) verification PASSES with the correct signer set and threshold.
func TestVerify_PassesWithAuthorizedSet(t *testing.T) {
	price70k, _ := new(big.Int).SetString("70000000000000000000000", 10) // 70000 * 1e18
	f := newFixture(t, 4, price70k)
	set := signerSet(f.addrs)
	if err := VerifyReportSigners(f.ctx, f.blob, f.rs, f.ss, f.vs, set, 3); err != nil {
		t.Fatalf("expected verification to pass, got: %v", err)
	}
	// Also works decoded end-to-end from the envelope.
	ctx, blob, rs, ss, vs, err := DecodeFullReport(f.fullBytes)
	if err != nil {
		t.Fatalf("DecodeFullReport: %v", err)
	}
	if err := VerifyReportSigners(ctx, blob, rs, ss, vs, set, 3); err != nil {
		t.Fatalf("expected verification to pass end-to-end, got: %v", err)
	}
}

// (iii) verification FAILS when a signer is removed from the authorized set.
func TestVerify_FailsWhenSignerRemoved(t *testing.T) {
	f := newFixture(t, 4, big.NewInt(1))
	// Remove one signer from the authorized set.
	set := signerSet(f.addrs[:3]) // only first 3 authorized; 4th is unauthorized
	err := VerifyReportSigners(f.ctx, f.blob, f.rs, f.ss, f.vs, set, 3)
	if err == nil {
		t.Fatalf("expected verification to fail when a recovered signer is unauthorized")
	}
}

// (iv) verification FAILS on a tampered price byte (digest no longer matches the
// signatures, so recovered signers won't be in the set).
func TestVerify_FailsOnTamperedPrice(t *testing.T) {
	f := newFixture(t, 4, big.NewInt(50000))
	set := signerSet(f.addrs)

	// Tamper one byte of the price field (offset 192..223). Flip the lowest byte.
	tampered := make([]byte, len(f.blob))
	copy(tampered, f.blob)
	tampered[v3PriceOffset+wordSize-1] ^= 0x01

	err := VerifyReportSigners(f.ctx, tampered, f.rs, f.ss, f.vs, set, 3)
	if err == nil {
		t.Fatalf("expected verification to fail on tampered price")
	}
}

// The observations timestamp is part of the signed report blob. A freshness
// check must use this value, never similarly named metadata from the outer HTTP
// response. Changing the signed timestamp invalidates the DON signatures.
func TestVerify_FailsOnTamperedObservationsTimestamp(t *testing.T) {
	f := newFixture(t, 4, big.NewInt(50000))
	set := signerSet(f.addrs)

	tampered := make([]byte, len(f.blob))
	copy(tampered, f.blob)
	// observationsTimestamp is word[2], right-aligned in bytes 64..95.
	tampered[3*wordSize-1] ^= 0x01

	if err := VerifyReportSigners(f.ctx, tampered, f.rs, f.ss, f.vs, set, 3); err == nil {
		t.Fatal("expected verification to fail on tampered observations timestamp")
	}
}

// (v) verification FAILS when fewer than threshold distinct authorized signers
// are present.
func TestVerify_FailsBelowThreshold(t *testing.T) {
	f := newFixture(t, 2, big.NewInt(99))
	set := signerSet(f.addrs)
	// Only 2 signatures present, but require 3.
	err := VerifyReportSigners(f.ctx, f.blob, f.rs, f.ss, f.vs, set, 3)
	if err == nil {
		t.Fatalf("expected verification to fail below threshold")
	}
}

// duplicate signatures must not count twice toward the distinct threshold.
func TestVerify_FailsOnDuplicateSignerPaddingThreshold(t *testing.T) {
	f := newFixture(t, 1, big.NewInt(123))
	set := signerSet(f.addrs)
	// Duplicate the single signer's signature to fake "two" signatures.
	rs := [][32]byte{f.rs[0], f.rs[0]}
	ss := [][32]byte{f.ss[0], f.ss[0]}
	vs := []byte{f.vs[0], f.vs[0]}
	err := VerifyReportSigners(f.ctx, f.blob, rs, ss, vs, set, 2)
	if err == nil {
		t.Fatalf("expected verification to fail: duplicate signer should not satisfy distinct threshold of 2")
	}
}

// RecoverReportSigners returns the exact known signer addresses (in order) for
// a synthetic report, without any authorization check or threshold.
func TestRecoverReportSigners_RoundTrip(t *testing.T) {
	price, _ := new(big.Int).SetString("64234120000000000000000", 10)
	f := newFixture(t, 4, price)

	// Recover from the in-memory fixture components.
	got, err := RecoverReportSigners(f.ctx, f.blob, f.rs, f.ss, f.vs)
	if err != nil {
		t.Fatalf("RecoverReportSigners: %v", err)
	}
	if len(got) != len(f.addrs) {
		t.Fatalf("recovered %d signers, want %d", len(got), len(f.addrs))
	}
	for i := range f.addrs {
		if got[i] != f.addrs[i] {
			t.Fatalf("signer %d mismatch: got 0x%x want 0x%x", i, got[i], f.addrs[i])
		}
	}

	// Also recover end-to-end from the ABI-encoded envelope.
	ctx, blob, rs, ss, vs, err := DecodeFullReport(f.fullBytes)
	if err != nil {
		t.Fatalf("DecodeFullReport: %v", err)
	}
	got2, err := RecoverReportSigners(ctx, blob, rs, ss, vs)
	if err != nil {
		t.Fatalf("RecoverReportSigners (end-to-end): %v", err)
	}
	if len(got2) != len(f.addrs) {
		t.Fatalf("end-to-end recovered %d signers, want %d", len(got2), len(f.addrs))
	}
	for i := range f.addrs {
		if got2[i] != f.addrs[i] {
			t.Fatalf("end-to-end signer %d mismatch: got 0x%x want 0x%x", i, got2[i], f.addrs[i])
		}
	}
}

// RecoverReportSigners rejects a component-length mismatch.
func TestRecoverReportSigners_LengthMismatch(t *testing.T) {
	f := newFixture(t, 2, big.NewInt(1))
	if _, err := RecoverReportSigners(f.ctx, f.blob, f.rs, f.ss, f.vs[:1]); err == nil {
		t.Fatalf("expected error on vs length mismatch")
	}
}

func TestParseSignerAddress(t *testing.T) {
	a, err := ParseSignerAddress("0x5b3ebc3622dd75f0a680c2b7e4613ad813c72f82")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if a[0] != 0x5b || a[19] != 0x82 {
		t.Fatalf("unexpected parse result %x", a)
	}
	if _, err := ParseSignerAddress("0xshort"); err == nil {
		t.Fatalf("expected error on short address")
	}
}

func TestFeedIDMatches(t *testing.T) {
	f := newFixture(t, 1, big.NewInt(1))
	hexID := "0x"
	for _, b := range f.feedID {
		const hexdigits = "0123456789abcdef"
		hexID += string(hexdigits[b>>4]) + string(hexdigits[b&0xf])
	}
	if !FeedIDMatches(f.feedID, hexID) {
		t.Fatalf("expected feedID to match %s", hexID)
	}
	if FeedIDMatches(f.feedID, "0xdeadbeef") {
		t.Fatalf("expected mismatch on wrong feedID")
	}
}
