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

// Package internal holds types shared across the javascript enricher's
// sub-packages without creating import cycles.
package internal

// FailedPackage identifies an (npm-name, version) pair that the
// materializer couldn't fetch / install OR that the post-materialize
// dep-graph walk couldn't locate on disk. Lives in internal/ to avoid
// dragging the materialize and scan packages into each other's import
// graphs just to share this struct.
//
// **Contract**: Version MUST be set when the failure pertains to a
// specific version. An empty Version is the explicit "all installed
// versions of this name are absent / unanalyzable" signal — every vuln
// matching the name is then Skipped regardless of its own version. Use
// the empty form ONLY when the entire package is missing from the
// resolved tree; otherwise pass a concrete Version so peers at other
// installed versions are not accidentally suppressed.
type FailedPackage struct {
	Name    string
	Version string
}

// VulnRef is a trimmed reference to a vulnerability as it travels through
// scan/ + corpus/. It bundles the OSV id, the access-path patterns from
// corpus, and a back-pointer to the PackageVuln for final signal emission.
type VulnRef struct {
	OSVID              string
	PackageName        string
	PackageVersion     string
	AccessPathPatterns []string
	// Any additional fields (e.g. VulnChainDetails equivalent) that later
	// tasks need should be added here, not re-threaded through signatures.
}

// Result is produced by scan.Scan per VulnRef. Ref points back to the
// originating request so callers can attribute the verdict 1:1 instead of
// keying on OSVID (which can repeat when one CVE affects multiple
// installed packages).
type Result struct {
	Ref        *VulnRef
	OSVID      string
	Reachable  bool // true = matched, false = confirmed unreachable
	Skipped    bool // true = we didn't actually analyze; emit no signal
	SkipReason string
}
