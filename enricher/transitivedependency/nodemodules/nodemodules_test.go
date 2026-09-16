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

package nodemodules_test

import (
	"maps"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher/transitivedependency/nodemodules"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin/config"
)

func TestEnrich(t *testing.T) {
	const dummyVersion = "1.2.3"

	testCases := []struct {
		name     string
		packages []*extractor.Package
		parents  map[string][]string
	}{
		{
			name:     "empty",
			packages: []*extractor.Package{},
			parents:  map[string][]string{},
		},
		{
			name: "no_related_packages",
			packages: []*extractor.Package{{
				ID:       "unrelated/ecosystem-1",
				Name:     "unrelated/ecosystem-1",
				Version:  dummyVersion,
				Metadata: &unrelatedMetadata{},
			}, {
				ID:       "unrelated/ecosystem-2",
				Name:     "unrelated/ecosystem-2",
				Version:  dummyVersion,
				Metadata: &unrelatedMetadata{},
			}},
			parents: map[string][]string{},
		},
		{
			name: "packages_with_metadata",
			packages: []*extractor.Package{{
				ID:      "@parent/parent",
				Name:    "@parent/parent",
				Version: dummyVersion,
				Metadata: &metadata.JavascriptPackageJSONMetadata{Dependencies: map[string]string{
					"@child/child": dummyVersion,
				}},
			}, {
				ID:       "@child/child",
				Name:     "@child/child",
				Version:  dummyVersion,
				Metadata: &metadata.JavascriptPackageJSONMetadata{},
			}},
			parents: map[string][]string{
				"@child/child": []string{"@parent/parent"},
			},
		},
		{
			name: "mixed",
			packages: []*extractor.Package{{
				ID:      "@parent/parent",
				Name:    "@parent/parent",
				Version: dummyVersion,
				Metadata: &metadata.JavascriptPackageJSONMetadata{Dependencies: map[string]string{
					"@child/child": dummyVersion,
				}},
			}, {
				ID:       "@child/child",
				Name:     "@child/child",
				Version:  dummyVersion,
				Metadata: &metadata.JavascriptPackageJSONMetadata{},
			}, {
				ID:       "unrelated/ecosystem",
				Name:     "unrelated/ecosystem",
				Version:  dummyVersion,
				Metadata: &unrelatedMetadata{},
			}},
			parents: map[string][]string{
				"@child/child": []string{"@parent/parent"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e, err := nodemodules.New(config.DefaultPluginConfig())
			if err != nil {
				t.Fatalf("New() error: %v", err)
			}

			inventory := &inventory.Inventory{Packages: tc.packages}
			if err := e.Enrich(t.Context(), nil, inventory); err != nil {
				t.Fatalf("Enrich() error: %v", err)
			}

			for _, pkg := range inventory.Packages {
				want := tc.parents[pkg.ID]
				got := slices.Collect(maps.Keys(pkg.ParentIDs))
				if diff := cmp.Diff(want, got, cmpopts.SortSlices(strings.Compare), cmpopts.EquateEmpty()); diff != "" {
					t.Errorf("Enrich() returned an unexpected diff for %s (-want +got): %v", pkg.ID, diff)
				}
			}
		})
	}
}

type unrelatedMetadata struct{}

func (*unrelatedMetadata) IsProtoable() {}
