package main

import (
	"strings"
	"testing"
)

func TestBuildInfo(t *testing.T) {
	info := BuildInfo()

	// Should contain version
	if !strings.Contains(info, Version) {
		t.Errorf("BuildInfo should contain Version, got: %s", info)
	}

	// Should contain git commit
	if !strings.Contains(info, GitCommit) {
		t.Errorf("BuildInfo should contain GitCommit, got: %s", info)
	}

	// Should contain build time
	if !strings.Contains(info, BuildTime) {
		t.Errorf("BuildInfo should contain BuildTime, got: %s", info)
	}

	// Should have expected format
	if !strings.Contains(info, "(") || !strings.Contains(info, ")") || !strings.Contains(info, "built") {
		t.Errorf("BuildInfo should have format 'VERSION (COMMIT) built TIME', got: %s", info)
	}
}

func TestBuildInfoDefaultValues(t *testing.T) {
	// Test default values are set
	if Version == "" {
		t.Error("Version should not be empty")
	}

	if GitCommit == "" {
		t.Error("GitCommit should not be empty")
	}

	if BuildTime == "" {
		t.Error("BuildTime should not be empty")
	}
}
