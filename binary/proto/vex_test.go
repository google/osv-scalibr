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

package proto_test

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/inventory/vex"
	"google.golang.org/protobuf/testing/protocmp"
)

// --- Struct to Proto

func TestPackageVEXToProto(t *testing.T) {
	testCases := []struct {
		desc    string
		v       *vex.PackageExploitabilitySignal
		want    *spb.PackageExploitabilitySignal
		wantErr error
	}{
		{
			desc: "nil",
			v:    nil,
			want: nil,
		},
		{
			desc: "matches_specific_vulns",
			v: &vex.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: vex.ComponentNotPresent,
				VulnIdentifiers: []string{
					"CVE-1234",
					"CVE-5678",
				},
			},
			want: &spb.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
				VulnFilter: &spb.PackageExploitabilitySignal_VulnIdentifiers{
					VulnIdentifiers: &spb.VulnIdentifiers{
						Identifiers: []string{
							"CVE-1234",
							"CVE-5678",
						},
					},
				},
			},
		},
		{
			desc: "matches_all_vulns",
			v: &vex.PackageExploitabilitySignal{
				Plugin:          "some-plugin",
				Justification:   vex.ComponentNotPresent,
				MatchesAllVulns: true,
			},
			want: &spb.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
				VulnFilter: &spb.PackageExploitabilitySignal_MatchesAllVulns{
					MatchesAllVulns: true,
				},
			},
		},
		{
			desc: "both_vuln_identifiers_and_matches_all_vulns_set",
			v: &vex.PackageExploitabilitySignal{
				Plugin:          "some-plugin",
				Justification:   vex.ComponentNotPresent,
				VulnIdentifiers: []string{"CVE-1234"},
				MatchesAllVulns: true,
			},
			wantErr: proto.ErrVulnIdentifiersAndMatchsAllSet,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageVEXToProto(tc.v)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("PackageVEXToProto(%v) returned error %v, want error %v", tc.v, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVEXToProto(%v) returned diff (-want +got):\n%s", tc.v, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil && tc.v != nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageVEXToStruct(got)
			if err != nil {
				t.Fatalf("PackageVEXToStruct(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.v, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVEXToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestFindingVEXToProto(t *testing.T) {
	testCases := []struct {
		desc string
		v    *vex.FindingExploitabilitySignal
		want *spb.FindingExploitabilitySignal
	}{
		{
			desc: "nil",
			v:    nil,
			want: nil,
		},
		{
			desc: "success",
			v: &vex.FindingExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: vex.ComponentNotPresent,
			},
			want: &spb.FindingExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.FindingVEXToProto(tc.v)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("FindingVEXToProto(%v) returned diff (-want +got):\n%s", tc.v, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB := proto.FindingVEXToStruct(got)
			if diff := cmp.Diff(tc.v, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("FindingVEXToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

// --- Proto to Struct

func TestPackageVEXToStruct(t *testing.T) {
	testCases := []struct {
		desc    string
		v       *spb.PackageExploitabilitySignal
		want    *vex.PackageExploitabilitySignal
		wantErr error
	}{
		{
			desc: "nil",
			v:    nil,
			want: nil,
		},
		{
			desc: "matches_specific_vulns",
			v: &spb.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
				VulnFilter: &spb.PackageExploitabilitySignal_VulnIdentifiers{
					VulnIdentifiers: &spb.VulnIdentifiers{
						Identifiers: []string{
							"CVE-1234",
							"CVE-5678",
						},
					},
				},
			},
			want: &vex.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: vex.ComponentNotPresent,
				VulnIdentifiers: []string{
					"CVE-1234",
					"CVE-5678",
				},
			},
		},
		{
			desc: "matches_all_vulns",
			v: &spb.PackageExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
				VulnFilter: &spb.PackageExploitabilitySignal_MatchesAllVulns{
					MatchesAllVulns: true,
				},
			},
			want: &vex.PackageExploitabilitySignal{
				Plugin:          "some-plugin",
				Justification:   vex.ComponentNotPresent,
				MatchesAllVulns: true,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.PackageVEXToStruct(tc.v)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("PackageVEXToStruct(%v) returned error %v, want error %v", tc.v, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVEXToStruct(%v) returned diff (-want +got):\n%s", tc.v, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil && tc.v != nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.PackageVEXToProto(got)
			if err != nil {
				t.Fatalf("PackageVEXToProto(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.v, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("PackageVEXToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestFindingVEXToStruct(t *testing.T) {
	testCases := []struct {
		desc string
		v    *spb.FindingExploitabilitySignal
		want *vex.FindingExploitabilitySignal
	}{
		{
			desc: "nil",
			v:    nil,
			want: nil,
		},
		{
			desc: "success",
			v: &spb.FindingExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
			},
			want: &vex.FindingExploitabilitySignal{
				Plugin:        "some-plugin",
				Justification: vex.ComponentNotPresent,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got := proto.FindingVEXToStruct(tc.v)
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("FindingVEXToStruct(%v) returned diff (-want +got):\n%s", tc.v, diff)
			}

			// Test the reverse conversion for completeness.
			gotPB := proto.FindingVEXToProto(got)
			if diff := cmp.Diff(tc.v, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("FindingVEXToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
