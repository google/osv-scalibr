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

package pomxml_test

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/pomxml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
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
				// Not a Java package.
				Name:     "abc",
				Version:  "1.0.0",
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath("testdata/poetry/poetry.lock"),
				Plugins:  []string{"python/poetrylock"},
			},
			{
				// Not extracted from a pom.xml
				Name:     "abc",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/java/gradle.lockfile"),
				Plugins:  []string{"java/gradlelockfile"},
			},
			{
				Name:     "org.direct:alice",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "alice",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.direct:bob",
				Version:  "2.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "bob",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.direct:chris",
				Version:  "3.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "chris",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
		},
	}

	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponse(t, "org/upstream/parent-pom/1.0/parent-pom-1.0.pom", []byte(`
	<project>
	  <groupId>org.upstream</groupId>
	  <artifactId>parent-pom</artifactId>
	  <version>1.0</version>
	  <packaging>pom</packaging>
		<dependencies>
      <dependency>
        <groupId>org.eve</groupId>
        <artifactId>eve</artifactId>
        <version>5.0.0</version>
      </dependency>
		</dependencies>
	</project>
	`))
	srv.SetResponse(t, "org/import/import/1.2.3/import-1.2.3.pom", []byte(`
	<project>
	  <groupId>org.import</groupId>
	  <artifactId>import</artifactId>
	  <version>1.2.3</version>
	  <packaging>pom</packaging>
	  <dependencyManagement>
      <dependencies>
        <dependency>
          <groupId>org.frank</groupId>
          <artifactId>frank</artifactId>
          <version>6.0.0</version>
        </dependency>
      </dependencies>
	  </dependencyManagement>
	</project>
	`))

	apiClient, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("%v", err)
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")

	enrichy, err := pomxml.New(&cpb.PluginConfig{})

	if err != nil {
		t.Fatalf("failed to create enricher: %v", err)
	}

	enrichy.(*pomxml.Enricher).DepClient = resolutionClient
	enrichy.(*pomxml.Enricher).MavenClient = apiClient

	err = enrichy.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("failed to enrich: %v", err)
	}

	wantInventory := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				// Not a Java package.
				Name:     "abc",
				Version:  "1.0.0",
				PURLType: purl.TypePyPi,
				Location: extractor.LocationFromPath("testdata/poetry/poetry.lock"),
				Plugins:  []string{"python/poetrylock"},
			},
			{
				// Not extracted from a pom.xml
				Name:     "abc",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/java/gradle.lockfile"),
				Plugins:  []string{"java/gradlelockfile"},
			},
			{
				Name:     "org.direct:alice",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "alice",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.direct:bob",
				Version:  "2.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "bob",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.direct:chris",
				Version:  "3.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "chris",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.transitive:chuck",
				Version:  "1.1.1",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "chuck",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.transitive:dave",
				Version:  "2.2.2",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "dave",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.transitive:eve",
				Version:  "3.3.3",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "eve",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.transitive:frank",
				Version:  "4.4.4",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "frank",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
		},
	}
	sort.Slice(inv.Packages, func(i, j int) bool {
		return inv.Packages[i].Name < inv.Packages[j].Name
	})
	if diff := cmp.Diff(wantInventory, inv); diff != "" {
		t.Errorf("%s.Enrich() diff (-want +got):\n%s", enrichy.Name(), diff)
	}
}

// TestEnricher_Enrich_NonJarFiltering verifies that non-jar dependencies are
// filtered out during transitive dependency resolution.
// This covers the edge cases:
//   - <type>zip</type> in dependencies (e.g. MuleSoft RAML) → skipped
//   - <type>pom</type> in dependencies → skipped
//   - <type>aar</type> in dependencyManagement → skipped
//   - <type>pom</type> without import scope in dependencyManagement → skipped
//   - no <type> (defaults to jar) → kept
//   - <type>jar</type> explicit → kept
func TestEnricher_Enrich_NonJarFiltering(t *testing.T) {
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: "testdata",
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "org.direct:alice",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "alice",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				Name:     "org.direct:bob",
				Version:  "2.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "bob",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
		},
	}

	apiClient, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "http://localhost:0")
	if err != nil {
		t.Fatalf("%v", err)
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")

	enrichy, err := pomxml.New(&cpb.PluginConfig{})

	if err != nil {
		t.Fatalf("failed to create enricher: %v", err)
	}

	enrichy.(*pomxml.Enricher).DepClient = resolutionClient
	enrichy.(*pomxml.Enricher).MavenClient = apiClient

	err = enrichy.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("failed to enrich: %v", err)
	}

	wantInventory := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				// Direct dep, no type specified (defaults to jar) → kept
				Name:     "org.direct:alice",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "alice",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				// Direct dep, explicit <type>jar</type> → kept
				Name:     "org.direct:bob",
				Version:  "2.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "bob",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			{
				// Transitive dep via alice → kept
				Name:     "org.transitive:chuck",
				Version:  "1.1.1",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "chuck",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			{
				// Transitive dep via alice → kept
				Name:     "org.transitive:dave",
				Version:  "2.2.2",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "dave",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			{
				// Transitive dep via bob → kept
				Name:     "org.transitive:eve",
				Version:  "3.3.3",
				PURLType: purl.TypeMaven,
				ScanRoot: "testdata",
				Location: extractor.LocationFromPath("testdata/transitive-nonjar.xml"),
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "eve",
					GroupID:      "org.transitive",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
			},
			// NOTE: The following are NOT expected in the output because they are filtered:
			// - org.nonjar:raml-spec (type=zip) — filtered from dependencies
			// - org.nonjar:some-pom (type=pom) — filtered from dependencies
			// - org.nonjar:android-lib (type=aar) — filtered from dependencyManagement
			// - org.nonjar:parent-only (type=pom, no import scope) — filtered from dependencyManagement
			// Also NOT expected: org.transitive:frank — it's in dependencyManagement (version pin only),
			// not in dependencies, so it won't appear unless something in the tree depends on it.
		},
	}
	sort.Slice(inv.Packages, func(i, j int) bool {
		return inv.Packages[i].Name < inv.Packages[j].Name
	})
	if diff := cmp.Diff(wantInventory, inv); diff != "" {
		t.Errorf("%s.Enrich() diff (-want +got):\n%s", enrichy.Name(), diff)
	}
}
