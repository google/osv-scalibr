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

// Package internal provides shared utilities for Python inventory extractors.
package internal

import (
	"regexp"
	"strings"
)

var (
	// reNormName matches separator runs in a Python package name per PEP 503.
	reNormName = regexp.MustCompile(`[-_.]+`)
	// reValidPkg validates a Python package name per PEP 508 / PyPA spec.
	// Matches the same set as python/requirements to avoid silent drops.
	reValidPkg = regexp.MustCompile(`(?i)^([A-Z0-9]|[A-Z0-9][A-Z0-9._-]*[A-Z0-9])$`)
	// reUnsupported matches version constraints that cannot be cleanly resolved to
	// a single concrete version: wildcards, less-than ranges, not-equal, or
	// compound (comma-separated) constraints.
	reUnsupported = regexp.MustCompile(`\*|<[^=]|,|!=`)
)

// NormalizeName normalizes a Python package name per PEP 503:
// trims whitespace, lowercases, and replaces any run of [-_.] with a single "-".
func NormalizeName(name string) string {
	return strings.ToLower(reNormName.ReplaceAllString(strings.TrimSpace(name), "-"))
}

// IsValidName reports whether name is a valid Python package name.
func IsValidName(name string) bool {
	return reValidPkg.MatchString(name)
}

// ParseVersionSpec parses the version-spec portion of a Pipfile dependency value
// (e.g. "==2.31.0", ">=", "~=4.2.0", "4.0.0", "*") and returns the bare
// version string and the comparator operator.
//
// For wildcards ("*"), empty strings, or unsupported constraints (compound
// constraints with commas, bare less-than "<" without "=", or not-equal
// "!="), both returned strings are empty — callers should still emit the
// package for dependency-resolution purposes and store the raw spec in
// metadata. This mirrors python/requirements behavior.
//
// For a bare version with no operator (e.g. "4.0.0"), equality is inferred:
// version is returned as-is and comparator is "==" so that Metadata.Requirement
// and Metadata.VersionComparator are consistent.
func ParseVersionSpec(spec string) (version, comparator string) {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "*" {
		return "", ""
	}
	if reUnsupported.FindString(spec) != "" {
		return "", ""
	}
	for _, sep := range []string{"==", ">=", "<=", "~=", ">"} {
		if v, ok := strings.CutPrefix(spec, sep); ok {
			return strings.TrimSpace(v), sep
		}
	}
	// Bare version (no operator) — infer equality so VersionComparator and
	// Requirement agree (e.g. "4.0.0" → version="4.0.0", comparator=="==").
	return spec, "=="
}

// BuildRequirement constructs a pip-compatible requirement string from a
// normalized package name and its raw version spec value.
//
//   - If spec is empty or "*", returns just the name (e.g. "flask").
//   - If spec begins with an operator, returns name+spec (e.g. "requests==2.31.0").
//   - If spec is a bare version (no leading operator), treats it as equality
//     and returns name+"=="+spec (e.g. "anyio==4.0.0").
func BuildRequirement(name, spec string) string {
	if spec == "" || spec == "*" {
		return name
	}
	if len(spec) > 0 && strings.ContainsRune("=><!~", rune(spec[0])) {
		return name + spec
	}
	// Bare version — assume equality.
	return name + "==" + spec
}
