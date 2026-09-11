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

package java_test

import (
	"archive/zip"
	"bytes"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/purl"

	"github.com/google/osv-scalibr/plugin/config"
)

const (
	testJar               = "javareach-test.jar"
	reachableJar          = "reachable-dep-test.jar"
	unreachableJar        = "unreachable-dep-test.jar"
	reachableGroupID      = "mock.reachable"
	reachableArtifactID   = "foo"
	unreachableGroupID    = "mock.unreachable"
	unreachableArtifactID = "bar"
	version               = "1.0.0"
)

func TestScan(t *testing.T) {
	jar := filepath.Join("testdata", reachableJar)

	enr, err := java.New(config.DefaultPluginConfig())
	if err != nil {
		t.Fatalf("Javareach enricher init failed: %s", err)
	}
	enr.(*java.Enricher).Client = mockClient(t)

	pkgs := setupPackages([]string{testJar})
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: jar,
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: pkgs,
	}
	err = enr.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("Javareach enrich failed: %s", err)
	}

	for _, pkg := range inv.Packages {
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == reachableArtifactID {
			for _, signal := range pkg.ExploitabilitySignals {
				if signal.Justification == vex.VulnerableCodeNotInExecutePath {
					t.Fatalf("Javareach enrich failed, expected %s to be reachable, but marked as unreachable", pkg.Name)
				}
			}
		}
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == unreachableArtifactID {
			hasUnreachableSignal := false
			for _, signal := range pkg.ExploitabilitySignals {
				if signal.Justification == vex.VulnerableCodeNotInExecutePath {
					hasUnreachableSignal = true
				}
			}
			if !hasUnreachableSignal {
				t.Fatalf("Javareach enrich failed, expected %s to be unreachable, but marked as reachable", pkg.Name)
			}
		}
	}
}

func mockClient(t *testing.T) *http.Client {
	t.Helper()
	// mock a server to act as Maven Central to avoid network requests.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path
		if strings.Contains(requestPath, unreachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
		} else if strings.Contains(requestPath, reachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
		}
	}))

	originalURL := java.MavenBaseURL
	java.MavenBaseURL = server.URL

	t.Cleanup(func() {
		java.MavenBaseURL = originalURL
		server.Close()
	})

	return server.Client()
}

func setupPackages(names []string) []*extractor.Package {
	pkgs := []*extractor.Package{}
	var reachablePkgName = fmt.Sprintf("%s:%s", reachableGroupID, reachableArtifactID)
	var unreachablePkgName = fmt.Sprintf("%s:%s", unreachableGroupID, unreachableArtifactID)

	for _, n := range names {
		reachablePkg := &extractor.Package{
			Name:     reachablePkgName,
			Version:  version,
			PURLType: purl.TypeMaven,
			Metadata: &archivemeta.Metadata{ArtifactID: reachableArtifactID, GroupID: reachableGroupID},
			Location: extractor.LocationFromPath(filepath.Join("testdata", n)),
			Plugins:  []string{archive.Name},
		}

		unreachablePkg := &extractor.Package{
			Name:     unreachablePkgName,
			Version:  version,
			PURLType: purl.TypeMaven,
			Metadata: &archivemeta.Metadata{ArtifactID: unreachableArtifactID, GroupID: unreachableGroupID},
			Location: extractor.LocationFromPath(filepath.Join("testdata", n)),
			Plugins:  []string{archive.Name},
		}

		pkgs = append(pkgs, reachablePkg, unreachablePkg)
	}

	return pkgs
}

func TestGetMainClasses(t *testing.T) {
	testCases := []struct {
		desc     string
		manifest string
		want     []string
		wantErr  error
	}{
		{
			desc:     "single_main_class",
			manifest: "Manifest-Version: 1.0\nMain-Class: com.example.Main\n",
			want:     []string{"com/example/Main"},
		},
		{
			desc:     "start_class",
			manifest: "Manifest-Version: 1.0\nStart-Class: com.example.Application\n",
			want:     []string{"com/example/Application"},
		},
		{
			desc:     "wrapped_line",
			manifest: "Manifest-Version: 1.0\nMain-Class: com.example.verylongpackagename.\n MyMainClass\n",
			want:     []string{"com/example/verylongpackagename/MyMainClass"},
		},
		{
			desc:     "no_main_class",
			manifest: "Manifest-Version: 1.0\nCreated-By: 21.0.2\n",
			wantErr:  java.ErrNoMainClass,
		},
		{
			desc:     "empty_manifest",
			manifest: "",
			wantErr:  java.ErrNoMainClass,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			got, err := java.GetMainClasses(strings.NewReader(tc.manifest))
			if tc.wantErr != nil {
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("GetMainClasses() error = %v, wantErr = %v", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetMainClasses() unexpected error: %v", err)
			}
			if len(got) != len(tc.want) {
				t.Fatalf("GetMainClasses() got %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("GetMainClasses()[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

func TestScan_WithDependencyJarsWithoutMainClass(t *testing.T) {
	jar := filepath.Join("testdata", reachableJar)

	enr, err := java.New(config.DefaultPluginConfig())
	if err != nil {
		t.Fatalf("Javareach enricher init failed: %s", err)
	}
	enr.(*java.Enricher).Client = mockClient(t)

	// Scan includes the main application jar along with dependency jars that do not have Main-Class.
	pkgs := setupPackages([]string{testJar, reachableJar, unreachableJar})
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: jar,
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: pkgs,
	}
	err = enr.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("Javareach enrich failed: %s", err)
	}

	for _, pkg := range inv.Packages {
		if pkg.Location.PathOrEmpty() != filepath.Join("testdata", testJar) {
			continue
		}
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == reachableArtifactID {
			for _, signal := range pkg.ExploitabilitySignals {
				if signal.Justification == vex.VulnerableCodeNotInExecutePath {
					t.Fatalf("expected %s to be reachable, but marked as unreachable", pkg.Name)
				}
			}
		}
		if pkg.Metadata.(*archivemeta.Metadata).ArtifactID == unreachableArtifactID {
			hasUnreachableSignal := false
			for _, signal := range pkg.ExploitabilitySignals {
				if signal.Justification == vex.VulnerableCodeNotInExecutePath {
					hasUnreachableSignal = true
				}
			}
			if !hasUnreachableSignal {
				t.Fatalf("expected %s to be unreachable, but marked as reachable", pkg.Name)
			}
		}
	}
}

func TestScan_SkipJarWithMavenDirButNoMainClass(t *testing.T) {
	// Create a temporary JAR with META-INF/maven and META-INF/MANIFEST.MF without Main-Class.
	depJarPath := filepath.Join("testdata", "dep-no-main-test.jar")
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	manifestWriter, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("failed to create manifest in zip: %v", err)
	}
	_, err = manifestWriter.Write([]byte("Manifest-Version: 1.0\nCreated-By: 21.0.2\n"))
	if err != nil {
		t.Fatalf("failed to write manifest: %v", err)
	}

	pomWriter, err := zw.Create("META-INF/maven/com.example/dep/pom.properties")
	if err != nil {
		t.Fatalf("failed to create pom.properties in zip: %v", err)
	}
	_, err = pomWriter.Write([]byte("groupId=com.example\nartifactId=dep\nversion=1.0.0\n"))
	if err != nil {
		t.Fatalf("failed to write pom.properties: %v", err)
	}

	if err := zw.Close(); err != nil {
		t.Fatalf("failed to close zip writer: %v", err)
	}

	if err := os.WriteFile(depJarPath, buf.Bytes(), 0644); err != nil {
		t.Fatalf("failed to write dep jar file: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Remove(depJarPath)
	})

	enr, err := java.New(config.DefaultPluginConfig())
	if err != nil {
		t.Fatalf("Javareach enricher init failed: %s", err)
	}
	enr.(*java.Enricher).Client = mockClient(t)

	depPkg := &extractor.Package{
		Name:     "com.example:dep",
		Version:  "1.0.0",
		PURLType: purl.TypeMaven,
		Metadata: &archivemeta.Metadata{ArtifactID: "dep", GroupID: "com.example"},
		Location: extractor.LocationFromPath(depJarPath),
		Plugins:  []string{archive.Name},
	}

	pkgs := append(setupPackages([]string{testJar}), depPkg)
	input := enricher.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: filepath.Join("testdata", reachableJar),
			FS:   scalibrfs.DirFS("."),
		},
	}
	inv := inventory.Inventory{
		Packages: pkgs,
	}

	err = enr.Enrich(t.Context(), &input, &inv)
	if err != nil {
		t.Fatalf("Javareach enrich should succeed by skipping jar without Main-Class, got: %v", err)
	}
}
