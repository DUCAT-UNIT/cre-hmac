package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestWorkflowConfigFiles keeps deployable JSON files on the same strict
// parsing and validation path used by the workflow. It catches misspelled or
// stale fields before a deployment silently selects a zero value.
func TestWorkflowConfigFiles(t *testing.T) {
	patterns := []string{
		"../hmac/config*.json",
		"../hmac-dev/config*.json",
		"../cre-tester/config*.json",
	}
	matched := 0
	for _, pattern := range patterns {
		paths, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatalf("invalid config glob %q: %v", pattern, err)
		}
		for _, path := range paths {
			matched++
			t.Run(filepath.Base(filepath.Dir(path))+"/"+filepath.Base(path), func(t *testing.T) {
				data, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("read config: %v", err)
				}
				var cfg Config
				if err := json.Unmarshal(data, &cfg); err != nil {
					t.Fatalf("strict config parse: %v", err)
				}
				if err := cfg.Validate(); err != nil {
					t.Fatalf("config validation: %v", err)
				}
			})
		}
	}
	if matched == 0 {
		t.Fatal("no workflow config files found")
	}
}
