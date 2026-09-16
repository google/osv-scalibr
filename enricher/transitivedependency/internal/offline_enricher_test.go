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

package internal_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
)

var (
	pkgParent = &extractor.Package{
		ID: "pkg-id-parent", // Pre-populated ID, so we can hard-code the wanted output.
		Metadata: &fakeMetadata{
			directDependency("parent", "1.0.0", requirement("child", "2.3.4")),
		},
	}

	pkgChild = &extractor.Package{
		Metadata: &fakeMetadata{directDependency("child", "2.3.4")},
	}

	pkgChildLinkedToParent = &extractor.Package{
		ParentIDs: map[string]bool{"pkg-id-parent": true},
		Metadata:  &fakeMetadata{directDependency("child", "2.3.4")},
	}

	pkgOtherParent = &extractor.Package{
		Metadata: &fakeMetadata{
			directDependency("other-parent", "5.0.0", requirement("other-child", "6.0.0")),
		},
	}

	pkgParentMissingChild = &extractor.Package{
		Metadata: &fakeMetadata{
			directDependency("parent-no-child", "1.0.0", requirement("missing-from-inventory", "7.8.9")),
		},
	}

	pkgReqNoVersion = &extractor.Package{
		ID: "pkg-id-req-no-version",
		Metadata: &fakeMetadata{
			directDependency("parent-no-version", "3.0.1", requirement("other-child", "")),
		},
	}

	pkgOtherChild = &extractor.Package{
		Metadata: &fakeMetadata{directDependency("other-child", "6.0.0")},
	}

	pkgOtherChildLinkedToReqNoVersion = &extractor.Package{
		ParentIDs: map[string]bool{"pkg-id-req-no-version": true},
		Metadata:  &fakeMetadata{directDependency("other-child", "6.0.0")},
	}

	pkgUnrelated = &extractor.Package{
		Metadata: &fakeMetadata{nil},
	}

	pkgParentWithRels = &extractor.Package{
		ID: "pkg-id-parent",
		Metadata: &fakeMetadata{
			directDependency("parent", "1.0.0", requirement("child", "2.3.4")),
		},
		Location: extractor.PackageLocation{
			Related: []location.Location{
				{File: nil},
				{File: &location.File{Path: "path/to/parent.jar"}},
				{File: &location.File{Path: "path/to/parent.jar/inside"}},
			},
		},
	}

	pkgChildRelatedByLocation = &extractor.Package{
		Metadata: &fakeMetadata{directDependency("child", "2.3.4")},
		Location: extractor.PackageLocation{
			Related: []location.Location{
				{File: &location.File{Path: "path/to/parent.jar"}},
				{File: &location.File{Path: "path/to/parent.jar/other/inside"}},
			},
		},
	}

	pkgChildUnrelatedByLocation = &extractor.Package{
		Metadata: &fakeMetadata{directDependency("child", "2.3.4")},
		Location: extractor.PackageLocation{
			Related: []location.Location{
				{File: nil},
				{File: &location.File{Path: "path/to/unrelated.jar"}},
			},
		},
	}

	pkgChildRelatedByLocationLinkedToParent = &extractor.Package{
		ParentIDs: map[string]bool{"pkg-id-parent": true},
		Metadata:  &fakeMetadata{directDependency("child", "2.3.4")},
		Location: extractor.PackageLocation{
			Related: []location.Location{
				{File: &location.File{Path: "path/to/parent.jar"}},
				{File: &location.File{Path: "path/to/parent.jar/other/inside"}},
			},
		},
	}
)

func TestEnrich(t *testing.T) {
	testCases := []struct {
		name  string
		input *inventory.Inventory
		want  *inventory.Inventory
	}{
		{
			name:  "empty",
			input: &inventory.Inventory{},
			want:  &inventory.Inventory{},
		},
		{
			name:  "graph_connected",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgParent, pkgChild}},
			want:  &inventory.Inventory{Packages: []*extractor.Package{pkgParent, pkgChildLinkedToParent}},
		},
		{
			name:  "unrelated_package",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgUnrelated}},
			want:  &inventory.Inventory{Packages: []*extractor.Package{pkgUnrelated}},
		},
		{
			name:  "graph_disconnected",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgChild, pkgOtherParent}},
			want:  &inventory.Inventory{Packages: []*extractor.Package{pkgChild, pkgOtherParent}},
		},
		{
			name:  "child_not_in_inventory",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgParentMissingChild}},
			want:  &inventory.Inventory{Packages: []*extractor.Package{pkgParentMissingChild}},
		},
		{
			name: "child_related_by_location_is_selected",
			input: &inventory.Inventory{Packages: []*extractor.Package{
				pkgParentWithRels,
				pkgChildRelatedByLocation,
				pkgChildUnrelatedByLocation,
			}},
			want: &inventory.Inventory{Packages: []*extractor.Package{
				pkgParentWithRels,
				pkgChildRelatedByLocationLinkedToParent,
				pkgChildUnrelatedByLocation,
			}},
		},
		{
			name:  "no_version",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgReqNoVersion, pkgOtherChild}},
			want: &inventory.Inventory{Packages: []*extractor.Package{
				pkgReqNoVersion,
				pkgOtherChildLinkedToReqNoVersion,
			}},
		},
		{
			name:  "no_version_child_not_in_inventory",
			input: &inventory.Inventory{Packages: []*extractor.Package{pkgReqNoVersion}},
			want:  &inventory.Inventory{Packages: []*extractor.Package{pkgReqNoVersion}},
		}}

	copier := cpy.New(cpy.IgnoreAllUnexported())

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			got := copier.Copy(tc.input).(*inventory.Inventory)
			enricher := internal.NewOfflineEnricher(&nopPackageExtractor{})
			if err := enricher.Enrich(t.Context(), nil, got); err != nil {
				t.Fatalf("Enrich failed: %v", err)
			}
			if diff := cmp.Diff(tc.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("Enrich returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

type nopPackageExtractor struct{}

func (*nopPackageExtractor) Extract(pkg *extractor.Package) *internal.DirectDependency {
	return pkg.Metadata.(*fakeMetadata).Dependency
}

type fakeMetadata struct {
	Dependency *internal.DirectDependency
}

// There is no matching proto to serialize to, but the declaration is sufficient for this test.
func (*fakeMetadata) IsProtoable() {}
