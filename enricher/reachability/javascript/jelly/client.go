// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package jelly provides a subprocess wrapper around the Jelly static
// analyzer's CLI. The Client interface is mockable so scan/ can be tested
// without actually spawning jelly.
package jelly

import (
	"context"
	"time"
)

// Client is the mockable interface to Jelly.
type Client interface {
	// Available returns true if the jelly and node binaries are on PATH
	// and node is version >= 22.0.0.
	Available(ctx context.Context) bool

	// RunImportOnly runs `jelly --modules-only ...` for Phase 1 pre-pass.
	RunImportOnly(ctx context.Context, args ImportOnlyArgs) (ImportResult, error)

	// RunFullScan runs the expensive full-scan Phase 2 command.
	RunFullScan(ctx context.Context, args FullScanArgs) (ScanResult, error)
}

// ImportOnlyArgs is the input to RunImportOnly.
type ImportOnlyArgs struct {
	BaseDir          string
	EntryPoints      []string // positional; defaults to [BaseDir] if empty
	IncludePackages  []string // empty means --ignore-dependencies
	ExcludeEntries   []string
	ReachableFileOut string // path to --reachable-file
	Timeout          time.Duration
	MaxFileSize      int64 // bytes; 0 = jelly default (no cap)
}

// ImportResult is parsed from --reachable-file.
type ImportResult struct {
	ReachablePackages []ReachablePackage
}

// ReachablePackage is one entry in the --reachable-file output's "packages" array.
// Exact schema is pinned at runtime; for now we only need Name.
type ReachablePackage struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

// FullScanArgs is the input to RunFullScan.
type FullScanArgs struct {
	BaseDir             string
	EntryPoints         []string // positional
	VulnerabilitiesFile string   // path to --vulnerabilities <file>
	IncludePackages     []string // empty means --ignore-dependencies
	ExcludeEntries      []string
	MatchesFile         string        // path to --matches-file
	DiagnosticsFile     string        // path to --diagnostics-json
	Timeout             time.Duration // for jelly's internal -i flag
	MaxIndirections     int
	Approx              bool
	MaxFileSize         int64 // bytes; 0 = jelly default (no cap)
}

// ScanResult is parsed from --matches-file + --diagnostics-json.
type ScanResult struct {
	// Matches is a map of OSV id → source location strings
	// ("file:startLine:startCol:endLine:endCol"). An empty entry for a
	// submitted vuln id means Jelly analyzed it and found no matches.
	Matches map[string][]string

	Diagnostics     Diagnostics
	TimedOut        bool
	TerminatedEarly bool
	LowConfidence   bool

	// TerminationError carries the underlying subprocess error when
	// TerminatedEarly is true (e.g. missing jelly binary, an *exec.ExitError
	// describing the signal that killed it, or the Windows "unsupported"
	// sentinel). nil otherwise. Operators see it in the orchestrator's
	// "all heuristics exhausted; last error" diagnostic.
	TerminationError error
}

// Diagnostics is a subset of Jelly's --diagnostics-json output.
// Fields are optional; only AnalyzerRounds drives LowConfidence today.
type Diagnostics struct {
	AnalyzerRounds int  `json:"analyzerRounds,omitempty"`
	Aborted        bool `json:"aborted,omitempty"`
	Timeout        bool `json:"timeout,omitempty"`
	LowMemory      bool `json:"lowmemory,omitempty"`
	RangeError     bool `json:"rangeError,omitempty"`
}
