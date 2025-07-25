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
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/binary/proto"
	spb "github.com/google/osv-scalibr/binary/proto/scan_result_go_proto"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"google.golang.org/protobuf/testing/protocmp"
)

var (
	genericFindingStruct1 = &inventory.GenericFinding{
		Adv: &inventory.GenericFindingAdvisory{
			ID: &inventory.AdvisoryID{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Title:          "Title",
			Description:    "Description",
			Recommendation: "Recommendation",
			Sev:            inventory.SeverityMedium,
		},
		Target: &inventory.GenericFindingTargetDetails{
			Extra: "extra details",
		},
		Plugins: []string{"cve/cve-1234-finder", "cve/cve-1234-enricher"},
		ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{
			Plugin:        "some-plugin",
			Justification: vex.ComponentNotPresent,
		}},
	}

	genericFindingProto1 = &spb.GenericFinding{
		Adv: &spb.GenericFindingAdvisory{
			Id: &spb.AdvisoryId{
				Publisher: "CVE",
				Reference: "CVE-1234",
			},
			Title:          "Title",
			Description:    "Description",
			Recommendation: "Recommendation",
			Sev:            spb.SeverityEnum_MEDIUM,
		},
		Target: &spb.GenericFindingTargetDetails{
			Extra: "extra details",
		},
		Plugins: []string{"cve/cve-1234-finder", "cve/cve-1234-enricher"},
		ExploitabilitySignals: []*spb.FindingExploitabilitySignal{{
			Plugin:        "some-plugin",
			Justification: spb.VexJustification_COMPONENT_NOT_PRESENT,
		}},
	}
)

func TestGenericFindingToProto(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		finding *inventory.GenericFinding
		want    *spb.GenericFinding
		wantErr error
	}{
		{
			desc:    "success",
			finding: genericFindingStruct1,
			want:    genericFindingProto1,
		},
		{
			desc:    "nil",
			finding: nil,
			want:    nil,
		},
		{
			desc: "missing advisory",
			finding: func(f *inventory.GenericFinding) *inventory.GenericFinding {
				f = copier.Copy(f).(*inventory.GenericFinding)
				f.Adv = nil
				return f
			}(genericFindingStruct1),
			want:    nil,
			wantErr: proto.ErrAdvisoryMissing,
		},
		{
			desc: "missing advisory ID",
			finding: func(f *inventory.GenericFinding) *inventory.GenericFinding {
				f = copier.Copy(f).(*inventory.GenericFinding)
				f.Adv.ID = nil
				return f
			}(genericFindingStruct1),
			want:    nil,
			wantErr: proto.ErrAdvisoryIDMissing,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.GenericFindingToProto(tc.finding)
			if !errors.Is(err, tc.wantErr) {
				t.Errorf("GenericFindingToProto(%v) returned error %v, want error %v", tc.finding, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("GenericFindingToProto(%v) returned diff (-want +got):\n%s", tc.finding, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.GenericFindingToStruct(got)
			if err != nil {
				t.Fatalf("GenericFindingToStruct(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.finding, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("GenericFindingToStruct(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}

func TestGenericFindingToStruct(t *testing.T) {
	copier := cpy.New(
		cpy.IgnoreAllUnexported(),
	)

	testCases := []struct {
		desc    string
		finding *spb.GenericFinding
		want    *inventory.GenericFinding
		wantErr error
	}{
		{
			desc:    "success",
			finding: genericFindingProto1,
			want:    genericFindingStruct1,
		},
		{
			desc:    "nil",
			finding: nil,
			want:    nil,
		},
		{
			desc: "missing advisory",
			finding: func(f *spb.GenericFinding) *spb.GenericFinding {
				f = copier.Copy(f).(*spb.GenericFinding)
				f.Adv = nil
				return f
			}(genericFindingProto1),
			want:    nil,
			wantErr: proto.ErrAdvisoryMissing,
		},
		{
			desc: "missing advisory ID",
			finding: func(f *spb.GenericFinding) *spb.GenericFinding {
				f = copier.Copy(f).(*spb.GenericFinding)
				f.Adv.Id = nil
				return f
			}(genericFindingProto1),
			want:    nil,
			wantErr: proto.ErrAdvisoryIDMissing,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := proto.GenericFindingToStruct(tc.finding)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("GenericFindingToStruct(%v) returned error %v, want error %v", tc.finding, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got, protocmp.Transform()); diff != "" {
				t.Fatalf("GenericFindingToStruct(%v) returned diff (-want +got):\n%s", tc.finding, diff)
			}

			// No need to test the reverse conversion if the result is nil.
			if got == nil {
				return
			}

			// Test the reverse conversion for completeness.
			gotPB, err := proto.GenericFindingToProto(got)
			if err != nil {
				t.Fatalf("GenericFindingToProto(%v) returned error %v, want nil", got, err)
			}
			if diff := cmp.Diff(tc.finding, gotPB, protocmp.Transform()); diff != "" {
				t.Fatalf("GenericFindingToProto(%v) returned diff (-want +got):\n%s", got, diff)
			}
		})
	}
}
