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

package jelly

import (
	"strconv"
	"time"
)

// flags accumulates argv tokens for a jelly subprocess invocation. Each
// method names exactly one jelly CLI flag and chains so the build site
// reads top-to-bottom in the order jelly will see the arguments.
//
// To add a new jelly flag: add one method here, no other call sites need
// to know what the flag spelling is.
type flags struct {
	args []string
}

func newFlags() *flags { return &flags{} }

// BaseDir adds `-b PATH` (jelly's analysis base directory).
func (f *flags) BaseDir(path string) *flags {
	f.args = append(f.args, "-b", path)
	return f
}

// Timeout adds `-i SECONDS` (jelly's internal time limit). Sub-second
// durations are rounded UP to 1s — jelly interprets `-i 0` as "no timeout"
// and runJelly's wall-clock guard collapses to a 0-duration context that
// would fire immediately. Negative durations are also floored at 1s.
func (f *flags) Timeout(t time.Duration) *flags {
	secs := int(t.Seconds())
	if t > 0 && secs < 1 {
		secs = 1
	}
	if secs < 1 {
		secs = 1
	}
	f.args = append(f.args, "-i", strconv.Itoa(secs))
	return f
}

// Vulnerabilities adds `-v PATH` (file containing vulnerability patterns).
func (f *flags) Vulnerabilities(path string) *flags {
	f.args = append(f.args, "-v", path)
	return f
}

// ModulesOnly adds `--modules-only` (Phase 1 import-reachability mode).
func (f *flags) ModulesOnly() *flags {
	f.args = append(f.args, "--modules-only")
	return f
}

// VulnerabilitiesFull adds `--vulnerabilities-full` (use the full
// pattern-matching mode instead of the lightweight default).
func (f *flags) VulnerabilitiesFull() *flags {
	f.args = append(f.args, "--vulnerabilities-full")
	return f
}

// ReachableFile adds `--reachable-file PATH` (Phase 1 output JSON).
func (f *flags) ReachableFile(path string) *flags {
	f.args = append(f.args, "--reachable-file", path)
	return f
}

// MatchesFile adds `--matches-file PATH` (Phase 2 matches output JSON).
func (f *flags) MatchesFile(path string) *flags {
	f.args = append(f.args, "--matches-file", path)
	return f
}

// DiagnosticsJSON adds `--diagnostics-json PATH` (run diagnostics output).
func (f *flags) DiagnosticsJSON(path string) *flags {
	f.args = append(f.args, "--diagnostics-json", path)
	return f
}

// IgnoreUnresolved adds `--ignore-unresolved` (don't fail on missing
// modules; treat them as opaque). Always safe to include for our use
// case.
func (f *flags) IgnoreUnresolved() *flags {
	f.args = append(f.args, "--ignore-unresolved")
	return f
}

// Scope translates an include-set into either
// `--include-packages PKG...` or `--ignore-dependencies`. The two flags
// are mutually exclusive in jelly's CLI; an empty include-set means
// "deps are opaque".
func (f *flags) Scope(includePackages []string) *flags {
	if len(includePackages) == 0 {
		f.args = append(f.args, "--ignore-dependencies")
		return f
	}
	f.args = append(f.args, "--include-packages")
	f.args = append(f.args, includePackages...)
	return f
}

// ExcludeEntries adds `--exclude-entries GLOB...` when entries is
// non-empty; otherwise the flag is omitted entirely.
func (f *flags) ExcludeEntries(entries []string) *flags {
	if len(entries) == 0 {
		return f
	}
	f.args = append(f.args, "--exclude-entries")
	f.args = append(f.args, entries...)
	return f
}

// MaxIndirections adds `--max-indirections N` when n > 0; jelly's
// internal default applies when omitted.
func (f *flags) MaxIndirections(n int) *flags {
	if n > 0 {
		f.args = append(f.args, "--max-indirections", strconv.Itoa(n))
	}
	return f
}

// Approx adds `--approx` (cheap-approximation mode) only when on is true.
func (f *flags) Approx(on bool) *flags {
	if on {
		f.args = append(f.args, "--approx")
	}
	return f
}

// MaxFileSize adds `--max-file-size BYTES` when n > 0; jelly skips any source
// file larger than the given size. Defends against minified vendor bundles
// that would otherwise dominate analysis time and memory.
func (f *flags) MaxFileSize(n int64) *flags {
	if n > 0 {
		f.args = append(f.args, "--max-file-size", strconv.FormatInt(n, 10))
	}
	return f
}

// EntryPointsOrDefault appends the trailing positional entry-point paths.
// When entries is empty, defaults to [defaultEntry] so jelly always has
// at least one entry argument.
func (f *flags) EntryPointsOrDefault(defaultEntry string, entries []string) *flags {
	if len(entries) == 0 {
		entries = []string{defaultEntry}
	}
	f.args = append(f.args, entries...)
	return f
}

// Build returns the accumulated argv tokens.
func (f *flags) Build() []string { return f.args }
