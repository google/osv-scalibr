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

package fakeenricher_test

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/testing/fakeenricher"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestName(t *testing.T) {
	tests := []struct {
		name string
		cfg  *fakeenricher.Config
	}{
		{
			name: "no name",
			cfg:  &fakeenricher.Config{},
		},
		{
			name: "name",
			cfg:  &fakeenricher.Config{Name: "some enricher"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeenricher.MustNew(t, tc.cfg)
			got := e.Name()
			if got != tc.cfg.Name {
				t.Errorf("Enricher{%+v}.Name() = %q, want %q", tc.cfg, got, tc.cfg.Name)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	tests := []struct {
		name string
		cfg  *fakeenricher.Config
	}{
		{
			name: "zero version",
			cfg:  &fakeenricher.Config{},
		},
		{
			name: "positive version",
			cfg:  &fakeenricher.Config{Version: 7},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeenricher.MustNew(t, tc.cfg)
			got := e.Version()
			if got != tc.cfg.Version {
				t.Errorf("Enricher{%+v}.Version() = %d, want %d", tc.cfg, got, tc.cfg.Version)
			}
		})
	}
}

func TestRequirements(t *testing.T) {
	tests := []struct {
		name string
		cfg  *fakeenricher.Config
	}{
		{
			name: "no requirements",
			cfg:  &fakeenricher.Config{},
		},
		{
			name: "some requirements",
			cfg: &fakeenricher.Config{
				Capabilities: &plugin.Capabilities{
					Network:  plugin.NetworkOnline,
					DirectFS: true,
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeenricher.MustNew(t, tc.cfg)
			got := e.Requirements()
			if diff := cmp.Diff(tc.cfg.Capabilities, got); diff != "" {
				t.Errorf("Enricher{%+v}.Requirements() returned unexpected diff (-want +got):\n%s", tc.cfg, diff)
			}
		})
	}
}

func TestRequiredPlugins(t *testing.T) {
	tests := []struct {
		name string
		cfg  *fakeenricher.Config
	}{
		{
			name: "no required plugins",
			cfg:  &fakeenricher.Config{},
		},
		{
			name: "some required plugins",
			cfg:  &fakeenricher.Config{RequiredPlugins: []string{"plugin1", "plugin2"}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeenricher.MustNew(t, tc.cfg)
			got := e.RequiredPlugins()
			if diff := cmp.Diff(tc.cfg.RequiredPlugins, got); diff != "" {
				t.Errorf("Enricher{%+v}.RequiredPlugins() returned unexpected diff (-want +got):\n%s", tc.cfg, diff)
			}
		})
	}
}

func TestEnrich(t *testing.T) {
	input1 := &enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			FS: fstest.MapFS{
				"/some/file.text":  {Mode: fs.ModePerm},
				"/another/file.md": {Mode: fs.ModePerm},
			},
			Path: "root",
		},
	}
	inventory1 := &inventory.Inventory{
		Packages: []*extractor.Package{{
			Name:    "package1",
			Version: "1.0",
		}},
		PackageVulns: []*inventory.PackageVuln{
			{
				Vulnerability: &osvschema.Vulnerability{Id: "CVE-9012"},
			},
		},
		GenericFindings: []*inventory.GenericFinding{{
			Adv: &inventory.GenericFindingAdvisory{
				ID: &inventory.AdvisoryID{
					Publisher: "CVE",
					Reference: "CVE-2024-12345",
				},
			},
		}},
	}

	inventory2 := &inventory.Inventory{
		Packages: []*extractor.Package{{
			Name:    "package2",
			Version: "2.0",
		}, {
			Name:    "package3",
			Version: "3.0",
		}},
		PackageVulns: []*inventory.PackageVuln{{
			Vulnerability: &osvschema.Vulnerability{Id: "CVE-9012"},
		}},
		GenericFindings: []*inventory.GenericFinding{{
			Adv: &inventory.GenericFindingAdvisory{
				ID: &inventory.AdvisoryID{
					Publisher: "CVE",
					Reference: "CVE-2024-12345",
				},
			},
		}, {
			Adv: &inventory.GenericFindingAdvisory{
				ID: &inventory.AdvisoryID{
					Publisher: "CVE",
					Reference: "CVE-2024-67890",
				},
				Recommendation: "do something",
			},
			Target: &inventory.GenericFindingTargetDetails{
				Extra: "extra info",
			},
		}},
	}

	tests := []struct {
		name    string
		cfg     *fakeenricher.Config
		input   *enricher.ScanInput
		inv     *inventory.Inventory
		wantInv *inventory.Inventory
		wantErr error
	}{
		{
			name: "nothing to enrich",
			cfg: &fakeenricher.Config{
				WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
					fakeenricher.MustHash(t, nil, &inventory.Inventory{}): fakeenricher.InventoryAndErr{
						Inventory: &inventory.Inventory{},
					},
				},
			},
			inv:     &inventory.Inventory{},
			wantInv: &inventory.Inventory{},
		},
		{
			name: "enrich packages and findings",
			cfg: &fakeenricher.Config{
				WantEnrich: map[uint64]fakeenricher.InventoryAndErr{
					fakeenricher.MustHash(t, input1, inventory1): fakeenricher.InventoryAndErr{
						Inventory: inventory2,
					},
				},
			},
			input:   input1,
			inv:     inventory1,
			wantInv: inventory2,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := fakeenricher.MustNew(t, tc.cfg)
			gotErr := e.Enrich(t.Context(), tc.input, tc.inv)
			if !cmp.Equal(gotErr, tc.wantErr, cmpopts.EquateErrors()) {
				t.Errorf("Enricher{%+v}.Enrich(%+v, %+v) error: got %v, want %v\n", tc.cfg, tc.input, tc.inv, gotErr, tc.wantErr)
			}
			if diff := cmp.Diff(tc.wantInv, tc.inv, protocmp.Transform()); diff != "" {
				t.Errorf("Enricher{%+v}.Enrich(%+v, %+v) returned unexpected diff (-want +got):\n%s", tc.cfg, tc.input, tc.inv, diff)
			}
		})
	}
}
