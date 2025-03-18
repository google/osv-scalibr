// Copyright 2025 Google LLC
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

// Package remediation has the configuration options for vulnerability remediation.
package remediation

import (
	"math"
	"slices"

	resolutionimpl "github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/severity"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/guidedremediation/resolution"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Options is the configuration for remediation.
type Options struct {
	ResolutionOpts resolution.Options
	IgnoreVulns    []string // Vulnerability IDs to ignore
	ExplicitVulns  []string // If set, only consider these vulnerability IDs & ignore all others

	DevDeps     bool    // Whether to consider vulnerabilities in dev dependencies
	MinSeverity float64 // Minimum vulnerability CVSS score to consider
	MaxDepth    int     // Maximum depth of dependency to consider vulnerabilities for (e.g. 1 for direct only)

	UpgradeConfig upgrade.Config // Allowed upgrade levels per package.
}

// DefaultOptions creates a default initialized remediation configuration.
func DefaultOptions() Options {
	return Options{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}
}

// MatchVuln checks whether a found vulnerability should be considered according to the remediation options.
func (opts Options) MatchVuln(v resolutionimpl.Vulnerability) bool {
	if opts.matchID(v, opts.IgnoreVulns) {
		return false
	}

	if !opts.DevDeps && v.DevOnly {
		return false
	}

	return opts.matchSeverity(v) && opts.matchDepth(v)
}

func (opts Options) matchID(v resolutionimpl.Vulnerability, ids []string) bool {
	if slices.Contains(ids, v.OSV.ID) {
		return true
	}

	for _, id := range v.OSV.Aliases {
		if slices.Contains(ids, id) {
			return true
		}
	}

	return false
}

func (opts Options) matchSeverity(v resolutionimpl.Vulnerability) bool {
	maxScore := -1.0
	severities := v.OSV.Severity
	if len(severities) == 0 {
		// There are no top-level severity, see if there are individual affected[].severity field.
		severities = []osvschema.Severity{}
		for _, sg := range v.Subgraphs {
			inv := vulns.VKToInventory(sg.Nodes[sg.Dependency].Version)
			// Make and match a dummy OSV record per affected[] entry to determine which applies.
			for _, affected := range v.OSV.Affected {
				if vulns.IsAffected(&osvschema.Vulnerability{Affected: []osvschema.Affected{affected}}, inv) {
					severities = append(severities, affected.Severity...)
					break
				}
			}
		}
	}

	for _, sev := range severities {
		if score, err := severity.CalculateScore(sev); err == nil { // skip errors
			maxScore = max(maxScore, score)
		}
	}

	// CVSS scores are meant to only be to 1 decimal place
	// and we want to avoid something being falsely rejected/included due to floating point precision.
	// Multiply and round to only consider relevant parts of the score.
	return math.Round(10*maxScore) >= math.Round(10*opts.MinSeverity) ||
		maxScore < 0 // Always include vulns with unknown severities
}

func (opts Options) matchDepth(v resolutionimpl.Vulnerability) bool {
	if opts.MaxDepth <= 0 {
		return true
	}

	for _, sg := range v.Subgraphs {
		if sg.Nodes[0].Distance <= opts.MaxDepth {
			return true
		}
	}

	return false
}
