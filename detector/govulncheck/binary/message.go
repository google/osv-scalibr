// Copyright 2024 Google LLC
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

package binary

// govulncheckMessage contains the relevant parts of the json output of govulncheck.
type govulncheckMessage struct {
	OSV *osvEntry `json:"osv,omitempty"`
}

// osvEntry represents a vulnerability in the Go OSV format, documented
// in https://go.dev/security/vuln/database#schema.
type osvEntry struct {
	// ID is a unique identifier for the vulnerability.
	ID string
	// Aliases is a list of IDs for the same vulnerability in other
	// databases (CVE, GSHA)
	Aliases []string
	// Summary gives a one-line, English textual summary of the vulnerability.
	// It is recommended that this field be kept short, on the order of no more
	// than 120 characters.
	Summary string
	// Details contains additional English textual details about the vulnerability.
	Details string
	// Affected contains information on the modules and versions
	// affected by the vulnerability.
	Affected []affected
}
type affected struct {
	// The affected Go module. Required.
	// Note that this field is called "package" in the OSV specification.
	Module module `json:"package"`
	// The module version ranges affected by the vulnerability.
	Ranges []vulnRange `json:"ranges,omitempty"`
	// Details on the affected packages and symbols within the module.
	EcosystemSpecific ecosystemSpecific `json:"ecosystem_specific"`
}
type module struct {
	// The Go module path.
	Path string `json:"name"`
}

// The affected versions of the vulnerable module.
type vulnRange struct {
	// Events is a list of versions representing the ranges in which
	// the module is vulnerable.
	Events []rangeEvent `json:"events"`
}

// rangeEvent describes a single module version that either
// introduces or fixes a vulnerability.
type rangeEvent struct {
	// Introduced is a version that introduces the vulnerability.
	Introduced string `json:"introduced,omitempty"`
	// Fixed is a version that fixes the vulnerability.
	Fixed string `json:"fixed,omitempty"`
}

// ecosystemSpecific contains additional information about the vulnerable
// module for the Go ecosystem.
type ecosystemSpecific struct {
	// Packages is the list of affected packages within the module.
	Packages []affectedPackage `json:"imports,omitempty"`
}

// affectedPackage contains additional information about an affected package.
type affectedPackage struct {
	// Path is the package import path.
	Path string `json:"path,omitempty"`
	// GOOS is the execution operating system where the symbols appear.
	GOOS []string `json:"goos,omitempty"`
	// GOARCH specifies the execution architecture where the symbols appear.
	GOARCH []string `json:"goarch,omitempty"`
	// Symbols is a list of function and method names affected by
	// this vulnerability.
	Symbols []string `json:"symbols,omitempty"`
}
