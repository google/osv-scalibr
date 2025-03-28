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

package remediation

import (
	"math"
	"slices"

	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/severity"
	"github.com/google/osv-scalibr/guidedremediation/internal/vulns"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// MatchVuln checks whether a found vulnerability should be considered according to the remediation options.
func MatchVuln(opts options.RemediationOptions, v resolution.Vulnerability) bool {
	if matchID(v, opts.IgnoreVulns) {
		return false
	}

	if !opts.DevDeps && v.DevOnly {
		return false
	}

	return matchSeverity(v, opts.MinSeverity) && matchDepth(v, opts.MaxDepth)
}

func matchID(v resolution.Vulnerability, ids []string) bool {
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

func matchSeverity(v resolution.Vulnerability, minSeverity float64) bool {
	maxScore := -1.0
	severities := v.OSV.Severity
	if len(severities) == 0 {
		// There are no top-level severity, see if there are individual affected[].severity field.
		severities = []osvschema.Severity{}
		for _, sg := range v.Subgraphs {
			inv := vulns.VKToPackage(sg.Nodes[sg.Dependency].Version)
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
	return math.Round(10*maxScore) >= math.Round(10*minSeverity) ||
		maxScore < 0 // Always include vulns with unknown severities
}

func matchDepth(v resolution.Vulnerability, maxDepth int) bool {
	if maxDepth <= 0 {
		return true
	}

	for _, sg := range v.Subgraphs {
		if sg.Nodes[0].Distance <= maxDepth {
			return true
		}
	}

	return false
}
