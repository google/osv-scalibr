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
	"slices"
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

// TestEnricher_Enrich_Reactor exercises the multi-module ("reactor") case:
// two sibling pom.xml files in the same scan, one depending on the other.
// The sibling is not published to any Maven registry, so without
// reactor-aware resolution this scan would fail with a 404 lookup error.
func TestEnricher_Enrich_Reactor(t *testing.T) {
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: "testdata",
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			// Direct external dep declared by sibling-a.
			{
				Name:     "org.direct:alice",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/reactor/sibling-a/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "alice",
					GroupID:      "org.direct",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			// Reactor-internal dep declared by sibling-a. The extractor would
			// surface this; we expect the enricher to not error out trying to
			// fetch it from a remote registry.
			{
				Name:     "com.example.reactor:sibling-b",
				Version:  "1.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/reactor/sibling-a/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "sibling-b",
					GroupID:      "com.example.reactor",
					IsTransitive: false,
					DepGroupVals: []string{},
				},
			},
			// Direct external dep declared by sibling-b.
			{
				Name:     "org.direct:bob",
				Version:  "2.0.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("testdata/reactor/sibling-b/pom.xml"),
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

	// Mock HTTP server: deliberately empty. Any request out to a registry
	// for a reactor-internal coordinate would 404 here, which is exactly
	// the behavior we want to verify the enricher avoids.
	srv := clienttest.NewMockHTTPServer(t)
	apiClient, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("Setup: NewDefaultMavenRegistryAPIClient: %v", err)
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")

	enrichy, err := pomxml.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("Setup: pomxml.New() = %v, want nil", err)
	}
	enrichy.(*pomxml.Enricher).DepClient = resolutionClient
	enrichy.(*pomxml.Enricher).MavenClient = apiClient

	if err := enrichy.Enrich(t.Context(), &input, &inv); err != nil {
		t.Fatalf("Enrich() = %v, want nil for reactor scan", err)
	}

	// Verify that the reactor-internal dep was matched and tagged as enriched
	// (rather than being treated as a transitive dep that needed remote
	// resolution).
	var siblingPkg *extractor.Package
	for _, p := range inv.Packages {
		if p.Name == "com.example.reactor:sibling-b" {
			siblingPkg = p
			break
		}
	}
	if siblingPkg == nil {
		t.Fatal("sibling-b package = nil, want non-nil entry in enriched inventory")
	}
	if !slices.Contains(siblingPkg.Plugins, pomxml.Name) {
		t.Errorf("sibling-b plugins = %v, want to contain %q",
			siblingPkg.Plugins, pomxml.Name)
	}

	// Also verify the external dep declared by the sibling we depend on (bob)
	// shows up enriched: this confirms each module is processed independently.
	var bobPkg *extractor.Package
	for _, p := range inv.Packages {
		if p.Name == "org.direct:bob" {
			bobPkg = p
			break
		}
	}
	if bobPkg == nil {
		t.Fatal("org.direct:bob package = nil, want non-nil entry in enriched inventory")
	}
	if !slices.Contains(bobPkg.Plugins, pomxml.Name) {
		t.Errorf("org.direct:bob plugins = %v, want to contain %q",
			bobPkg.Plugins, pomxml.Name)
	}
}
