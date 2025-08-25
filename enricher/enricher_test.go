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

package enricher_test

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/testing/fakeenricher"
	"google.golang.org/protobuf/proto"
)

func TestRun(t *testing.T) {
	inventory1 := &inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "package1", Version: "1.0"},
		},
		GenericFindings: []*inventory.GenericFinding{
			{Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Publisher: "CVE", Reference: "CVE-2024-12345"}}},
		},
	}
	inventory2 := &inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "package2", Version: "2.0"},
			{Name: "package3", Version: "3.0"},
		},
		GenericFindings: []*inventory.GenericFinding{
			{Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Publisher: "CVE", Reference: "CVE-2024-12345"}}},
			{
				Adv: &inventory.GenericFindingAdvisory{
					ID:             &inventory.AdvisoryID{Publisher: "CVE", Reference: "CVE-2024-67890"},
					Recommendation: "do something",
				},
				Target: &inventory.GenericFindingTargetDetails{Extra: "extra info"},
			},
		},
	}
	inventory3 := &inventory.Inventory{
		Packages: []*extractor.Package{
			{Name: "package2", Version: "2.0"},
			{Name: "package3", Version: "3.0"},
			{Name: "package4", Version: "4.0"},
		},
		GenericFindings: []*inventory.GenericFinding{
			{
				Adv:    &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Publisher: "CVE", Reference: "CVE-2024-12345"}, Recommendation: "do something"},
				Target: &inventory.GenericFindingTargetDetails{Extra: "extra info"},
			},
			{
				Adv:    &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Publisher: "CVE", Reference: "CVE-2024-67890"}, Recommendation: "do something else"},
				Target: &inventory.GenericFindingTargetDetails{Extra: "extra info"},
			},
			{Adv: &inventory.GenericFindingAdvisory{ID: &inventory.AdvisoryID{Publisher: "GHSA", Reference: "GHSA-2024-45678"}, Recommendation: "none"}},
		},
	}

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		name    string
		cfg     *enricher.Config
		inv     *inventory.Inventory
		want    []*plugin.Status
		wantErr error
		wantInv *inventory.Inventory // Inventory after enrichment.
	}{
		{
			name: "no enrichers",
			cfg:  &enricher.Config{},
			want: nil,
		},
		{
			name: "enricher requires FS access but no scan root is provided",
			cfg: &enricher.Config{
				Enrichers: []enricher.Enricher{
					fakeenricher.MustNew(t, &fakeenricher.Config{
						Name: "enricher1", Version: 1,
						Capabilities: &plugin.Capabilities{DirectFS: true},
					}),
				},
			},
			inv:     inventory1,
			want:    nil,
			wantErr: enricher.ErrNoDirectFS,
			wantInv: inventory1, // Inventory is not modified.
		},
		{
			name: "some enrichers run successfully",
			cfg: &enricher.Config{
				Enrichers: []enricher.Enricher{
					fakeenricher.MustNew(t, &fakeenricher.Config{
						Name: "enricher1", Version: 1,
						WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
							fakeenricher.MustHash(t, &enricher.ScanInput{}, inventory1): fakeenricher.InventoryAndErr{Inventory: inventory2},
						},
					}),
					fakeenricher.MustNew(t, &fakeenricher.Config{
						Name: "enricher2", Version: 2,
						WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
							fakeenricher.MustHash(t, &enricher.ScanInput{}, inventory2): fakeenricher.InventoryAndErr{Inventory: inventory3},
						},
					}),
				},
			},
			inv: inventory1,
			want: []*plugin.Status{
				{Name: "enricher1", Version: 1, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
				{Name: "enricher2", Version: 2, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
			},
			wantInv: inventory3,
		},
		{
			name: "some fail and some succeed",
			cfg: &enricher.Config{
				Enrichers: []enricher.Enricher{
					fakeenricher.MustNew(t, &fakeenricher.Config{
						Name: "enricher1", Version: 1,
						WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
							fakeenricher.MustHash(t, &enricher.ScanInput{}, inventory1): fakeenricher.InventoryAndErr{Inventory: inventory2, Err: errors.New("some error")},
						},
					}),
					fakeenricher.MustNew(t, &fakeenricher.Config{
						Name: "enricher2", Version: 2,
						WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
							fakeenricher.MustHash(t, &enricher.ScanInput{}, inventory2): fakeenricher.InventoryAndErr{Inventory: inventory3},
						},
					}),
				},
			},
			inv: inventory1,
			want: []*plugin.Status{
				{Name: "enricher1", Version: 1, Status: &plugin.ScanStatus{Status: plugin.ScanStatusFailed, FailureReason: "some error"}},
				{Name: "enricher2", Version: 2, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
			},
			wantInv: inventory3,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Deep copy the inventory to avoid modifying the original inventory that is used in other tests.
			inv := copier.Copy(tc.inv).(*inventory.Inventory)
			got, err := enricher.Run(t.Context(), tc.cfg, inv)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Run(%+v) error: got %v, want %v\n", tc.cfg, err, tc.wantErr)
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Run(%+v) returned an unexpected diff of statuses (-want +got): %v", tc.cfg, diff)
			}
			if diff := cmp.Diff(tc.wantInv, inv); diff != "" {
				t.Errorf("Run(%+v) returned an unexpected diff of mutated inventory (-want +got): %v", tc.cfg, diff)
			}
		})
	}
}

type fakeVulnMatcher struct{}

func (fakeVulnMatcher) Name() string                       { return "vulnmatch/osvdev" }
func (fakeVulnMatcher) Version() int                       { return 0 }
func (fakeVulnMatcher) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (fakeVulnMatcher) RequiredPlugins() []string          { return nil }
func (fakeVulnMatcher) Enrich(_ context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	inv.PackageVulns = append(inv.PackageVulns, &inventory.PackageVuln{})
	return nil
}

// Expects the fakeVulnMatcher plugin to run first.
type fakeVEXFilterer struct{}

func (fakeVEXFilterer) Name() string                       { return "vex/filter" }
func (fakeVEXFilterer) Version() int                       { return 0 }
func (fakeVEXFilterer) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (fakeVEXFilterer) RequiredPlugins() []string          { return nil }
func (fakeVEXFilterer) Enrich(_ context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	if len(inv.PackageVulns) == 0 {
		return errors.New("vuln matcher didn't run before vex filterer")
	}
	inv.PackageVulns = nil
	return nil
}

// A third enricher that can run in any order.
type fakePackageAdder struct{}

func (fakePackageAdder) Name() string                       { return "fake-package-adder" }
func (fakePackageAdder) Version() int                       { return 0 }
func (fakePackageAdder) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (fakePackageAdder) RequiredPlugins() []string          { return nil }
func (fakePackageAdder) Enrich(_ context.Context, _ *enricher.ScanInput, inv *inventory.Inventory) error {
	inv.Packages = append(inv.Packages, &extractor.Package{})
	return nil
}

func TestRunEnricherOrdering(t *testing.T) {
	cfg := &enricher.Config{
		Enrichers: []enricher.Enricher{
			&fakePackageAdder{},
			&fakeVEXFilterer{},
			&fakeVulnMatcher{},
		},
	}
	inv := &inventory.Inventory{}

	wantInv := &inventory.Inventory{
		// One package (added by fakePackageAdder)
		Packages: []*extractor.Package{{}},
		// No vulns (removed by fakeVEXFilterer)
		PackageVulns: nil,
	}
	wantStatus := []*plugin.Status{
		{Name: "vulnmatch/osvdev", Version: 0, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
		{Name: "vex/filter", Version: 0, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
		{Name: "fake-package-adder", Version: 0, Status: &plugin.ScanStatus{Status: plugin.ScanStatusSucceeded}},
	}

	gotStatus, err := enricher.Run(t.Context(), cfg, inv)
	if err != nil {
		t.Errorf("Run(%+v) error: %v", cfg, err)
	}
	if diff := cmp.Diff(wantStatus, gotStatus); diff != "" {
		t.Errorf("Run(%+v) returned an unexpected diff of statuses (-want +got): %v", cfg, diff)
	}
	if diff := cmp.Diff(wantInv, inv); diff != "" {
		t.Errorf("Run(%+v) returned an unexpected diff of mutated inventory (-want +got): %v", cfg, diff)
	}
}
