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

package filter_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/enricher/vex/filter"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/mohae/deepcopy"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestEnrich(t *testing.T) {
	tests := []struct {
		desc string
		inv  *inventory.Inventory
		want *inventory.Inventory
	}{
		{
			desc: "no vulns",
			inv:  &inventory.Inventory{},
			want: &inventory.Inventory{},
		},
		{
			desc: "PackageVuln with VEX",
			inv: &inventory.Inventory{PackageVulns: []*inventory.PackageVuln{{
				Vulnerability:         osvschema.Vulnerability{Id: "CVE-123"},
				ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{Justification: vex.ComponentNotPresent}},
			}}},
			want: &inventory.Inventory{PackageVulns: []*inventory.PackageVuln{}},
		},
		{
			desc: "PackageVuln with no VEX",
			inv: &inventory.Inventory{PackageVulns: []*inventory.PackageVuln{{
				Vulnerability: osvschema.Vulnerability{Id: "CVE-123"},
			}}},
			want: &inventory.Inventory{PackageVulns: []*inventory.PackageVuln{{
				Vulnerability: osvschema.Vulnerability{Id: "CVE-123"},
			}}},
		},
		{
			desc: "GenericFinding with VEX",
			inv: &inventory.Inventory{GenericFindings: []*inventory.GenericFinding{{
				Adv:                   &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Reference: "CVE-123"}},
				ExploitabilitySignals: []*vex.FindingExploitabilitySignal{{Justification: vex.ComponentNotPresent}},
			}}},
			want: &inventory.Inventory{GenericFindings: []*inventory.GenericFinding{}},
		},
		{
			desc: "GenericFinding with no VEX",
			inv: &inventory.Inventory{GenericFindings: []*inventory.GenericFinding{{
				Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Reference: "CVE-123"}},
			}}},
			want: &inventory.Inventory{GenericFindings: []*inventory.GenericFinding{{
				Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Reference: "CVE-123"}},
			}}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.desc, func(t *testing.T) {
			inv := deepcopy.Copy(tc.inv).(*inventory.Inventory)
			if err := filter.New().Enrich(t.Context(), nil, inv); err != nil {
				t.Errorf("Enrich(%v) returned error: %v", tc.inv, err)
			}
			if diff := cmp.Diff(tc.want, inv, protocmp.Transform()); diff != "" {
				t.Errorf("Enrich(%v) returned diff (-want +got):\n%s", tc.inv, diff)
			}
		})
	}
}
