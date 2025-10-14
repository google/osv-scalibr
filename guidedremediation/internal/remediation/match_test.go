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

package remediation_test

import (
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/internal/remediation"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestMatchVuln(t *testing.T) {
	var (
		// ID: VULN-001, Dev: false, Severity: 6.6, Depth: 3, Aliases: CVE-111, OSV-2
		vuln1 = resolution.Vulnerability{
			OSV: &osvschema.Vulnerability{
				Id: "VULN-001",
				Severity: []*osvschema.Severity{
					{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:H"}, // 6.6
					{Type: osvschema.Severity_CVSS_V2, Score: "AV:L/AC:L/Au:S/C:P/I:P/A:C"},                   // 5.7
				},
				Aliases: []string{"CVE-111", "OSV-2"},
			},
			DevOnly: false,
			Subgraphs: []*resolution.DependencySubgraph{{
				Dependency: 3,
				Nodes: map[resolve.NodeID]resolution.GraphNode{
					3: {
						Distance: 0,
						Parents:  []resolve.Edge{{From: 2, To: 3}},
						Children: []resolve.Edge{},
					},
					2: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 1, To: 2}},
						Children: []resolve.Edge{{From: 2, To: 3}},
					},
					1: {
						Distance: 2,
						Parents:  []resolve.Edge{{From: 0, To: 1}},
						Children: []resolve.Edge{{From: 1, To: 2}},
					},
					0: {
						Distance: 3,
						Parents:  []resolve.Edge{},
						Children: []resolve.Edge{{From: 0, To: 1}},
					},
				},
			}},
		}
		// ID: VULN-002, Dev: true, Severity: N/A, Depth: 2
		vuln2 = resolution.Vulnerability{
			OSV: &osvschema.Vulnerability{
				Id: "VULN-002",
				// No severity
			},
			DevOnly: true,
			Subgraphs: []*resolution.DependencySubgraph{{
				Dependency: 3,
				Nodes: map[resolve.NodeID]resolution.GraphNode{
					3: {
						Distance: 0,
						Parents:  []resolve.Edge{{From: 2, To: 3}, {From: 1, To: 3}},
						Children: []resolve.Edge{},
					},
					2: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 1, To: 2}},
						Children: []resolve.Edge{{From: 2, To: 3}},
					},
					1: {
						Distance: 1,
						Parents:  []resolve.Edge{{From: 0, To: 1}},
						Children: []resolve.Edge{{From: 1, To: 2}, {From: 1, To: 3}},
					},
					0: {
						Distance: 2,
						Parents:  []resolve.Edge{},
						Children: []resolve.Edge{{From: 0, To: 1}},
					},
				},
			}},
		}

		// ID: VULN-003, Dev: false, Severity: 7.0, Depth: 1
		vuln3 = resolution.Vulnerability{
			OSV: &osvschema.Vulnerability{
				Id:      "VULN-003",
				Aliases: []string{"CVE-111", "OSV-2"},
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{
							Ecosystem: "npm",
							Name:      "pkg",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "0"},
									{Fixed: "1.9.1"},
								},
							},
						},
						Severity: []*osvschema.Severity{
							{Type: osvschema.Severity_CVSS_V4, Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H"}, // 9.9
						},
					},
					{
						Package: &osvschema.Package{
							Ecosystem: "npm",
							Name:      "pkg",
						},
						Ranges: []*osvschema.Range{
							{
								Type: osvschema.Range_SEMVER,
								Events: []*osvschema.Event{
									{Introduced: "2.0.0"},
									{Fixed: "2.9.9"},
								},
							},
						},
						Severity: []*osvschema.Severity{
							{Type: osvschema.Severity_CVSS_V4, Score: "CVSS:4.0/AV:L/AC:H/AT:P/PR:H/UI:A/VC:H/VI:H/VA:L/SC:N/SI:H/SA:H"}, // 7.0
						},
					},
				},
			},
			DevOnly: false,
			Subgraphs: []*resolution.DependencySubgraph{{
				Dependency: 1,
				Nodes: map[resolve.NodeID]resolution.GraphNode{
					1: {
						Distance: 0,
						Parents:  []resolve.Edge{{From: 0, To: 1}},
						Version: resolve.VersionKey{
							PackageKey: resolve.PackageKey{
								System: resolve.NPM,
								Name:   "pkg",
							},
							Version: "2.0.2",
						},
					},
					0: {
						Distance: 1,
						Parents:  []resolve.Edge{},
						Children: []resolve.Edge{{From: 0, To: 1}},
					},
				},
			}},
		}
	)
	tests := []struct {
		name string
		vuln resolution.Vulnerability
		opt  options.RemediationOptions
		want bool
	}{
		{
			name: "basic match",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:  true,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "accept depth",
			vuln: vuln2,
			opt: options.RemediationOptions{
				DevDeps:  true,
				MaxDepth: 2,
			},
			want: true,
		},
		{
			name: "reject depth",
			vuln: vuln2,
			opt: options.RemediationOptions{
				DevDeps:  true,
				MaxDepth: 1,
			},
			want: false,
		},
		{
			name: "accept severity",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.6,
			},
			want: true,
		},
		{
			name: "reject severity",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 6.7,
			},
			want: false,
		},
		{
			name: "accept unknown severity",
			vuln: vuln2,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 10.0,
			},
			want: true,
		},
		{
			name: "accept non-dev",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: true,
		},
		{
			name: "reject dev",
			vuln: vuln2,
			opt: options.RemediationOptions{
				DevDeps:  false,
				MaxDepth: -1,
			},
			want: false,
		},
		{
			name: "reject ID excluded",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"VULN-001"},
			},
			want: false,
		},
		{
			name: "accept matching multiple",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:     false,
				MaxDepth:    3,
				MinSeverity: 5.0,
				IgnoreVulns: []string{"VULN-999"},
			},
			want: true,
		},
		{
			name: "reject excluded ID in alias",
			vuln: vuln1,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				IgnoreVulns: []string{"OSV-2"},
			},
			want: false,
		},
		{
			name: "check per-affected severity",
			vuln: vuln3,
			opt: options.RemediationOptions{
				DevDeps:     true,
				MaxDepth:    -1,
				MinSeverity: 8.0,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := remediation.MatchVuln(tt.opt, tt.vuln); got != tt.want {
				t.Errorf("MatchVuln() = %v, want %v", got, tt.want)
			}
		})
	}
}
