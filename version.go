package main

// Version information - populated at build time via ldflags
// Build with: go build -ldflags "-X main.Version=v1.0.0 -X main.GitCommit=$(git rev-parse --short HEAD) -X main.BuildTime=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
var (
	// Version is the semantic version of the release
	Version = "dev"

	// GitCommit is the git commit hash
	GitCommit = "unknown"

	// BuildTime is the UTC build timestamp
	BuildTime = "unknown"
)

// BuildInfo returns version information as a formatted string
func BuildInfo() string {
	return Version + " (" + GitCommit + ") built " + BuildTime
}
