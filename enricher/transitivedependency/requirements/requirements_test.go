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

package requirements_test

import (
	"context"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/extractor"
	requirementsextractor "github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
)

func TestEnricher_Enrich(t *testing.T) {
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: "testdata",
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				// Not a Python package.
				Name:      "abc:xyz",
				Version:   "1.0.0",
				PURLType:  purl.TypeMaven,
				Locations: []string{"testdata/maven/pom.xml"},
				Plugins:   []string{"java/pomxml"},
			},
			{
				// Not extracted in requirements.txt.
				Name:      "abc",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/poetry/poetry.lock"},
				Plugins:   []string{"python/poetrylock"},
			},
			{
				Name:      "alice",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{Requirement: "alice"},
				Plugins:   []string{"python/requirements"},
			},
			{
				Name:      "bob",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", Requirement: "bob==2.0.0"},
				Plugins:   []string{"python/requirements"},
			},
			{
				// Hash checking mode.
				Name:      "hash1",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/hash/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "hash1==1.0.0"},
				Plugins:   []string{"python/requirements"},
			},
			{
				// Hash checking mode.
				Name:      "hash2",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/hash/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:456"}, Requirement: "hash2==2.0.0"},
				Plugins:   []string{"python/requirements"},
			},
		},
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe.yaml")
	enricher := requirements.NewEnricher(resolutionClient)
	err := enricher.Enrich(context.Background(), &input, &inv)
	if err != nil {
		t.Fatalf("failed to enrich: %v", err)
	}

	wantInventory := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				// Not extracted in requirements.txt.
				Name:      "abc",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/poetry/poetry.lock"},
				Plugins:   []string{"python/poetrylock"},
			},
			{
				// Not a Python package.
				Name:      "abc:xyz",
				Version:   "1.0.0",
				PURLType:  purl.TypeMaven,
				Locations: []string{"testdata/maven/pom.xml"},
				Plugins:   []string{"java/pomxml"},
			},
			{
				Name:      "alice",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{Requirement: "alice"},
				Plugins:   []string{"python/requirements", "resolution/requirements"},
			},
			{
				Name:      "bob",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", Requirement: "bob==2.0.0"},
				Plugins:   []string{"python/requirements", "resolution/requirements"},
			},
			{
				Name:      "chuck",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Plugins:   []string{"resolution/requirements"},
			},
			{
				Name:      "dave",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Plugins:   []string{"resolution/requirements"},
			},
			{
				Name:      "eve",
				Version:   "1.5.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Plugins:   []string{"resolution/requirements"},
			},
			{
				Name:      "frank",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/requirements.txt"},
				Plugins:   []string{"resolution/requirements"},
			},
			{
				// Hash checking mode.
				Name:      "hash1",
				Version:   "1.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/hash/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:123"}, Requirement: "hash1==1.0.0"},
				Plugins:   []string{"python/requirements"},
			},
			{
				// Hash checking mode.
				Name:      "hash2",
				Version:   "2.0.0",
				PURLType:  purl.TypePyPi,
				Locations: []string{"testdata/hash/requirements.txt"},
				Metadata:  &requirementsextractor.Metadata{VersionComparator: "==", HashCheckingModeValues: []string{"sha256:456"}, Requirement: "hash2==2.0.0"},
				Plugins:   []string{"python/requirements"},
			},
		},
	}
	sort.Slice(inv.Packages, func(i, j int) bool {
		return inv.Packages[i].Name < inv.Packages[j].Name
	})
	if diff := cmp.Diff(wantInventory, inv); diff != "" {
		t.Errorf("%s.Enrich() diff (-want +got):\n%s", enricher.Name(), diff)
	}
}
