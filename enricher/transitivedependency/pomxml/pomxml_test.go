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
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
	"github.com/google/osv-scalibr/clients/resolution"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/mockidgenerator"
	"github.com/google/osv-scalibr/enricher/transitivedependency/pomxml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin/config/configtest"
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
				ID:       "id-for-alice",
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
				ID:       "id-for-bob",
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
				ID:       "id-for-chris",
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

	enrichy, err := pomxml.New(configtest.NewFakePluginConfig())

	if err != nil {
		t.Fatalf("failed to create enricher: %v", err)
	}

	enrichy.(*pomxml.Enricher).DepClient = resolutionClient
	enrichy.(*pomxml.Enricher).MavenClient = apiClient
	enrichy.(*pomxml.Enricher).IDGenerator = &mockidgenerator.MockIDGenerator{}

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
				ID:       "id-for-alice",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.direct:bob",
				ID:       "id-for-bob",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.direct:chris",
				ID:       "id-for-chris",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.transitive:chuck",
				ID:       "dummy-id-org.transitive:chuck",
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
				ParentIDs: map[string]bool{"id-for-alice": true},
			},
			{
				Name:     "org.transitive:dave",
				ID:       "dummy-id-org.transitive:dave",
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
				ParentIDs: map[string]bool{"id-for-alice": true},
			},
			{
				Name:     "org.transitive:eve",
				ID:       "dummy-id-org.transitive:eve",
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
				ParentIDs: map[string]bool{"id-for-bob": true},
			},
			{
				Name:     "org.transitive:frank",
				ID:       "dummy-id-org.transitive:frank",
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
				ParentIDs: map[string]bool{"id-for-chris": true},
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
				ID:       "id-for-alice",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.direct:bob",
				ID:       "id-for-bob",
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
				ParentIDs: map[string]bool{"root": true},
			},
		},
	}

	apiClient, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "http://localhost:0")
	if err != nil {
		t.Fatalf("%v", err)
	}

	resolutionClient := clienttest.NewMockResolutionClient(t, "testdata/universe/basic-universe.yaml")

	enrichy, err := pomxml.New(configtest.NewFakePluginConfig())

	if err != nil {
		t.Fatalf("failed to create enricher: %v", err)
	}

	enrichy.(*pomxml.Enricher).DepClient = resolutionClient
	enrichy.(*pomxml.Enricher).MavenClient = apiClient
	enrichy.(*pomxml.Enricher).IDGenerator = &mockidgenerator.MockIDGenerator{}

	err = enrichy.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("failed to enrich: %v", err)
	}

	wantInventory := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				// Direct dep, no type specified (defaults to jar) → kept
				Name:     "org.direct:alice",
				ID:       "id-for-alice",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				// Direct dep, explicit <type>jar</type> → kept
				Name:     "org.direct:bob",
				ID:       "id-for-bob",
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
				ParentIDs: map[string]bool{"root": true},
			},
			{
				// Transitive dep via alice → kept
				Name:     "org.transitive:chuck",
				ID:       "dummy-id-org.transitive:chuck",
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
				ParentIDs: map[string]bool{"id-for-alice": true},
			},
			{
				// Transitive dep via alice → kept
				Name:     "org.transitive:dave",
				ID:       "dummy-id-org.transitive:dave",
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
				ParentIDs: map[string]bool{"id-for-alice": true},
			},
			{
				// Transitive dep via bob → kept
				Name:     "org.transitive:eve",
				ID:       "dummy-id-org.transitive:eve",
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
				ParentIDs: map[string]bool{"id-for-bob": true},
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

func TestEnricher_Enrich_LocalModules(t *testing.T) {
	tempDir := t.TempDir()

	// Create root parent pom.xml, defining modules a and b
	err := os.WriteFile(filepath.Join(tempDir, "pom.xml"), []byte(`
	<project>
		<groupId>org.example</groupId>
		<artifactId>parent</artifactId>
		<version>1.0</version>
		<packaging>pom</packaging>
		<modules>
			<module>module-a</module>
			<module>module-b</module>
		</modules>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-c/pom.xml (isolated parent for module-c and module-d)
	err = os.Mkdir(filepath.Join(tempDir, "parent-c"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-c", "pom.xml"), []byte(`
	<project>
		<groupId>org.example</groupId>
		<artifactId>parent-c</artifactId>
		<version>1.0</version>
		<packaging>pom</packaging>
		<modules>
			<module>module-c</module>
			<module>module-d</module>
		</modules>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-e/pom.xml (isolated parent for module-e and module-f)
	err = os.Mkdir(filepath.Join(tempDir, "parent-e"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-e", "pom.xml"), []byte(`
	<project>
		<groupId>org.example</groupId>
		<artifactId>parent-e</artifactId>
		<version>1.0</version>
		<packaging>pom</packaging>
		<modules>
			<module>module-e</module>
			<module>module-f</module>
		</modules>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create module-a/pom.xml (points to valid parent)
	err = os.Mkdir(filepath.Join(tempDir, "module-a"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "module-a", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent</artifactId>
			<version>1.0</version>
		</parent>
		<artifactId>module-a</artifactId>
		<dependencies>
			<dependency>
				<groupId>org.example</groupId>
				<artifactId>module-b</artifactId>
				<version>1.0</version>
			</dependency>
		</dependencies>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create module-b/pom.xml (declares dependencies under a default active profile)
	err = os.Mkdir(filepath.Join(tempDir, "module-b"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "module-b", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent</artifactId>
			<version>1.0</version>
		</parent>
		<artifactId>module-b</artifactId>
		<profiles>
			<profile>
				<id>default</id>
				<activation>
					<activeByDefault>true</activeByDefault>
				</activation>
				<dependencies>
					<dependency>
						<groupId>org.external</groupId>
						<artifactId>external-a</artifactId>
						<version>2.0</version>
					</dependency>
				</dependencies>
			</profile>
		</profiles>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-c/module-c/pom.xml (parent version is empty, uses parent-c)
	err = os.MkdirAll(filepath.Join(tempDir, "parent-c", "module-c"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-c", "module-c", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent-c</artifactId>
			<relativePath>../pom.xml</relativePath>
		</parent>
		<artifactId>module-c</artifactId>
		<dependencies>
			<dependency>
				<groupId>org.example</groupId>
				<artifactId>module-d</artifactId>
				<version>1.0</version>
			</dependency>
		</dependencies>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-c/module-d/pom.xml (points to valid parent-c)
	err = os.MkdirAll(filepath.Join(tempDir, "parent-c", "module-d"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-c", "module-d", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent-c</artifactId>
			<version>1.0</version>
			<relativePath>../pom.xml</relativePath>
		</parent>
		<artifactId>module-d</artifactId>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-e/module-e/pom.xml (points to valid parent-e)
	err = os.MkdirAll(filepath.Join(tempDir, "parent-e", "module-e"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-e", "module-e", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent-e</artifactId>
			<version>1.0</version>
			<relativePath>../pom.xml</relativePath>
		</parent>
		<artifactId>module-e</artifactId>
		<dependencies>
			<dependency>
				<groupId>org.example</groupId>
				<artifactId>module-f</artifactId>
				<version>1.0</version>
			</dependency>
		</dependencies>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Create parent-e/module-f/pom.xml (points to valid parent-e)
	err = os.MkdirAll(filepath.Join(tempDir, "parent-e", "module-f"), 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.WriteFile(filepath.Join(tempDir, "parent-e", "module-f", "pom.xml"), []byte(`
	<project>
		<parent>
			<groupId>org.example</groupId>
			<artifactId>parent-e</artifactId>
			<version>1.0</version>
			<relativePath>../pom.xml</relativePath>
		</parent>
		<artifactId>module-f</artifactId>
		<dependencies>
			<dependency>
				<groupId>org.external</groupId>
				<artifactId>external-b</artifactId>
				<version>3.0</version>
			</dependency>
		</dependencies>
	</project>
	`), 0644)
	if err != nil {
		t.Fatal(err)
	}

	// Set up mock server
	srv := clienttest.NewMockHTTPServer(t)

	// Mock for module-b versions
	srv.SetResponse(t, "org/example/module-b/maven-metadata.xml", []byte(`
	<metadata>
		<groupId>org.example</groupId>
		<artifactId>module-b</artifactId>
		<versioning>
			<versions>
				<version>1.0</version>
			</versions>
		</versioning>
	</metadata>
	`))

	// Mock for module-f versions
	srv.SetResponse(t, "org/example/module-f/maven-metadata.xml", []byte(`
	<metadata>
		<groupId>org.example</groupId>
		<artifactId>module-f</artifactId>
		<versioning>
			<versions>
				<version>1.0</version>
			</versions>
		</versioning>
	</metadata>
	`))

	// Mock for external-a versions
	srv.SetResponse(t, "org/external/external-a/maven-metadata.xml", []byte(`
	<metadata>
		<groupId>org.external</groupId>
		<artifactId>external-a</artifactId>
		<versioning>
			<versions>
				<version>2.0</version>
			</versions>
		</versioning>
	</metadata>
	`))

	// Mock for external-a POM
	srv.SetResponse(t, "org/external/external-a/2.0/external-a-2.0.pom", []byte(`
	<project>
		<groupId>org.external</groupId>
		<artifactId>external-a</artifactId>
		<version>2.0</version>
	</project>
	`))

	// Mock for external-b versions
	srv.SetResponse(t, "org/external/external-b/maven-metadata.xml", []byte(`
	<metadata>
		<groupId>org.external</groupId>
		<artifactId>external-b</artifactId>
		<versioning>
			<versions>
				<version>3.0</version>
			</versions>
		</versioning>
	</metadata>
	`))

	// Mock for external-b POM
	srv.SetResponse(t, "org/external/external-b/3.0/external-b-3.0.pom", []byte(`
	<project>
		<groupId>org.external</groupId>
		<artifactId>external-b</artifactId>
		<version>3.0</version>
	</project>
	`))

	apiClient, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("%v", err)
	}

	enrichy, err := pomxml.New(configtest.NewFakePluginConfig())
	if err != nil {
		t.Fatalf("failed to create enricher: %v", err)
	}

	enrichy.(*pomxml.Enricher).IDGenerator = &mockidgenerator.MockIDGenerator{}
	enrichy.(*pomxml.Enricher).MavenClient = apiClient
	enrichy.(*pomxml.Enricher).DepClient = resolution.NewMavenRegistryClientWithAPI(apiClient)

	// Prepare inventory:
	// - module-a/pom.xml and pom.xml (parent) are both in starting packages (keeps original coverage of parent registration)
	// - parent-c/module-c/pom.xml starts with parent without version (will fail to backtrack a parent)
	// - parent-e/module-e/pom.xml starts without parent in inventory (will succeed by backtracking parent-e)
	inv := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "org.example:module-b",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("module-a/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-b",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
			{
				Name:     "org.example:parent",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "parent",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
			{
				Name:     "org.example:module-d",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("parent-c/module-c/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-d",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
			{
				Name:     "org.example:module-f",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("parent-e/module-e/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-f",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
		},
	}

	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: tempDir,
			FS:   scalibrfs.DirFS(tempDir),
		},
	}

	err = enrichy.Enrich(t.Context(), &input, &inv)
	// We expect Enrich to return a joined error because the resolution
	// for parent-c/module-c/pom.xml fails due to parent lack of version.
	if err == nil {
		t.Fatalf("expected Enrich to return error but succeeded")
	}

	// Verify that the error is indeed in parent-c/module-c/pom.xml (empty parent version)
	// and NOT in module-a/pom.xml or parent-e/module-e/pom.xml.
	errStr := err.Error()
	if !strings.Contains(errStr, "failed resolution for parent-c/module-c/pom.xml") {
		t.Errorf("expected resolution failure for parent-c/module-c/pom.xml, got error: %v", err)
	}
	if strings.Contains(errStr, "failed resolution for module-a/pom.xml") {
		t.Errorf("expected module-a/pom.xml to resolve successfully, but got error: %v", err)
	}
	if strings.Contains(errStr, "failed resolution for parent-e/module-e/pom.xml") {
		t.Errorf("expected parent-e/module-e/pom.xml to resolve successfully, but got error: %v", err)
	}

	wantInventory := inventory.Inventory{
		Packages: []*extractor.Package{
			{
				Name:     "org.example:module-b",
				ID:       "dummy-id-org.example:module-b",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("module-a/pom.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-b",
					GroupID:      "org.example",
					IsTransitive: false,
				},
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.example:module-d",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("parent-c/module-c/pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-d",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
			{
				Name:     "org.example:module-f",
				ID:       "dummy-id-org.example:module-f",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("parent-e/module-e/pom.xml"),
				Plugins:  []string{"java/pomxml", "transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "module-f",
					GroupID:      "org.example",
					IsTransitive: false,
				},
				ParentIDs: map[string]bool{"root": true},
			},
			{
				Name:     "org.example:parent",
				ID:       "dummy-id-org.example:parent",
				Version:  "1.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("pom.xml"),
				Plugins:  []string{"java/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "parent",
					GroupID:      "org.example",
					IsTransitive: false,
				},
			},
			{
				Name:     "org.external:external-a",
				ID:       "dummy-id-org.external:external-a",
				Version:  "2.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("module-a/pom.xml"),
				ScanRoot: tempDir,
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "external-a",
					GroupID:      "org.external",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
				ParentIDs: map[string]bool{"dummy-id-org.example:module-b": true},
			},
			{
				Name:     "org.external:external-b",
				ID:       "dummy-id-org.external:external-b",
				Version:  "3.0",
				PURLType: purl.TypeMaven,
				Location: extractor.LocationFromPath("parent-e/module-e/pom.xml"),
				ScanRoot: tempDir,
				Plugins:  []string{"transitivedependency/pomxml"},
				Metadata: &javalockfile.Metadata{
					ArtifactID:   "external-b",
					GroupID:      "org.external",
					IsTransitive: true,
					DepGroupVals: []string{},
				},
				ParentIDs: map[string]bool{"dummy-id-org.example:module-f": true},
			},
		},
	}

	sort.Slice(inv.Packages, func(i, j int) bool {
		return inv.Packages[i].Name < inv.Packages[j].Name
	})
	sort.Slice(wantInventory.Packages, func(i, j int) bool {
		return wantInventory.Packages[i].Name < wantInventory.Packages[j].Name
	})

	if diff := cmp.Diff(wantInventory, inv); diff != "" {
		t.Errorf("%s.Enrich() diff (-want +got):\n%s", enrichy.Name(), diff)
	}
}
