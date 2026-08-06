package shared

import (
	"bytes"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"testing"

	ducatcrypto "ducat/crypto"
)

// TestRepositoryContainsNoCredentialLiterals is a narrow, dependency-free
// regression gate for the credential classes involved in the public-history
// incident. It scans every tracked file plus non-ignored untracked files, but
// never prints a matched value.
func TestRepositoryContainsNoCredentialLiterals(t *testing.T) {
	t.Parallel()

	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	repoRoot := filepath.Dir(filepath.Dir(currentFile))

	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = repoRoot
	listed, err := cmd.Output()
	if err != nil {
		t.Skipf("git checkout metadata unavailable: %v", err)
	}

	// Construct credential names in pieces so this test does not trigger its
	// own literal-assignment rules.
	privateAssignment := regexp.MustCompile(`(?i)` + "DUCAT_" + `PRIVATE_KEY\s*[:=]\s*["']?[0-9a-f]{64}`)
	clientAssignment := regexp.MustCompile(`(?i)` + "DUCAT_" + `CLIENT_SECRET\s*[:=]\s*["']?[A-Za-z0-9+/=_-]{32,}`)
	hex64 := regexp.MustCompile(`(?i)\b[0-9a-f]{64}\b`)
	alphaNum128 := regexp.MustCompile(`\b[A-Za-z0-9]{128}\b`)

	for _, rawPath := range bytes.Split(listed, []byte{0}) {
		if len(rawPath) == 0 {
			continue
		}
		relPath := string(rawPath)
		contents, err := os.ReadFile(filepath.Join(repoRoot, relPath))
		if err != nil {
			t.Errorf("read %s: %v", relPath, err)
			continue
		}

		if privateAssignment.Match(contents) {
			t.Errorf("%s contains a literal private-key environment assignment", relPath)
		}
		if clientAssignment.Match(contents) {
			t.Errorf("%s contains a literal client-secret environment assignment", relPath)
		}

		for _, candidate := range hex64.FindAll(contents, -1) {
			decoded := make([]byte, hex.DecodedLen(len(candidate)))
			if _, err := hex.Decode(decoded, candidate); err != nil {
				continue
			}
			if err := ducatcrypto.ValidateOraclePrivateKeyNotRevoked(decoded); err != nil {
				t.Errorf("%s contains the revoked oracle private key", relPath)
			}
			for i := range decoded {
				decoded[i] = 0
			}
		}

		for _, candidate := range alphaNum128.FindAll(contents, -1) {
			if err := ducatcrypto.ValidateClientSecretNotRevoked(candidate); err != nil {
				t.Errorf("%s contains the revoked Chainlink client secret", relPath)
			}
		}
	}
}
