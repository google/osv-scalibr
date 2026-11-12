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
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
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
	"github.com/google/osv-scalibr/plugin/config"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/fakefs"
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
			FS:   fakefs.DirFS(t, fakefs.CopyTestData(t, ".")),
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

func TestEnrich_DownloadHandling(t *testing.T) {
	resourceOnlyZip := buildResourceOnlyJAR(t)

	tests := []struct {
		name               string
		pkgs               []*extractor.Package
		handler            http.HandlerFunc
		closeServer        bool
		wantErr            bool
		wantUnreachableIDs []string
	}{
		{
			name: "partial_download_failure_404",
			pkgs: []*extractor.Package{
				newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar),
				newMavenPackage(unreachableGroupID, unreachableArtifactID, version, testJar),
				newMavenPackage("mock.missing", "baz", version, testJar),
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/foo-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
				case strings.Contains(r.URL.Path, "/bar-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
				default:
					http.NotFound(w, r)
				}
			},
			wantUnreachableIDs: []string{"mock.unreachable:bar@1.0.0"},
		},
		{
			name: "partial_download_failure_500",
			pkgs: []*extractor.Package{
				newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar),
				newMavenPackage(unreachableGroupID, unreachableArtifactID, version, testJar),
				newMavenPackage("mock.private", "internal-lib", version, testJar),
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/foo-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
				case strings.Contains(r.URL.Path, "/bar-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
				default:
					http.Error(w, "upstream gateway error", http.StatusInternalServerError)
				}
			},
			wantUnreachableIDs: []string{"mock.unreachable:bar@1.0.0"},
		},
		{
			name: "invalid_zip_response",
			pkgs: []*extractor.Package{
				newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar),
				newMavenPackage(unreachableGroupID, unreachableArtifactID, version, testJar),
				newMavenPackage("mock.corrupt", "portal-html", version, testJar),
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/foo-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
				case strings.Contains(r.URL.Path, "/bar-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
				default:
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte("<html>proxy error page</html>"))
				}
			},
			wantUnreachableIDs: []string{"mock.unreachable:bar@1.0.0"},
		},
		{
			name: "resource_only_jar_with_no_classes",
			pkgs: []*extractor.Package{
				newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar),
				newMavenPackage("mock.resources", "res-only", version, testJar),
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/foo-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
				case strings.Contains(r.URL.Path, "/res-only-1.0.0.jar"):
					w.Header().Set("Content-Type", "application/java-archive")
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write(resourceOnlyZip)
				default:
					http.NotFound(w, r)
				}
			},
			wantUnreachableIDs: []string{"mock.resources:res-only@1.0.0"},
		},
		{
			name: "same_artifact_different_versions_one_unmapped",
			pkgs: []*extractor.Package{
				newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar),
				newMavenPackage(unreachableGroupID, unreachableArtifactID, "1.0.0", testJar),
				newMavenPackage(unreachableGroupID, unreachableArtifactID, "2.0.0", testJar),
			},
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch {
				case strings.Contains(r.URL.Path, "/foo-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
				case strings.Contains(r.URL.Path, "/bar-1.0.0.jar"):
					http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
				default:
					http.NotFound(w, r)
				}
			},
			wantUnreachableIDs: []string{"mock.unreachable:bar@1.0.0"},
		},
		{
			name: "all_downloads_fail_503",
			pkgs: setupPackages([]string{testJar}),
			handler: func(w http.ResponseWriter, _ *http.Request) {
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
			},
			wantErr:            true,
			wantUnreachableIDs: nil,
		},
		{
			name:               "all_downloads_fail_network_error",
			pkgs:               setupPackages([]string{testJar}),
			handler:            http.NotFound,
			closeServer:        true,
			wantErr:            true,
			wantUnreachableIDs: nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			enr, err := java.New(config.DefaultPluginConfig())
			if err != nil {
				t.Fatalf("java.New() unexpected error: %v", err)
			}
			enr.(*java.Enricher).Client = mockClientWithHandler(t, tc.handler, tc.closeServer)

			input := enricher.ScanInput{
				ScanRoot: &scalibrfs.ScanRoot{
					Path: filepath.Join("testdata", reachableJar),
					FS:   scalibrfs.DirFS(fakefs.CopyTestData(t, ".")),
				},
			}
			inv := inventory.Inventory{
				Packages: tc.pkgs,
			}

			enrichErr := enr.Enrich(t.Context(), &input, &inv)
			if (enrichErr != nil) != tc.wantErr {
				t.Fatalf("Enrich() error = %v, wantErr %v", enrichErr, tc.wantErr)
			}

			gotUnreachableIDs := unreachablePackageIDs(inv.Packages)
			if !slices.Equal(gotUnreachableIDs, tc.wantUnreachableIDs) {
				t.Errorf("unreachable packages = %v, want %v", gotUnreachableIDs, tc.wantUnreachableIDs)
			}
		})
	}
}

func TestDefaultPackageFinder_IsMapped(t *testing.T) {
	var nilFinder *java.DefaultPackageFinder
	validPkg := newMavenPackage(reachableGroupID, reachableArtifactID, version, testJar)
	if nilFinder.IsMapped(validPkg) {
		t.Errorf("nil DefaultPackageFinder.IsMapped() = true, want false")
	}

	var emptyFinder java.DefaultPackageFinder
	if emptyFinder.IsMapped(nil) {
		t.Errorf("IsMapped(nil) = true, want false")
	}
	if emptyFinder.IsMapped(&extractor.Package{Name: "no-metadata", Version: version}) {
		t.Errorf("IsMapped(pkg without metadata) = true, want false")
	}
}

func mockClient(t *testing.T) *http.Client {
	t.Helper()
	return mockClientWithHandler(t, func(w http.ResponseWriter, r *http.Request) {
		requestPath := r.URL.Path
		if strings.Contains(requestPath, unreachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", unreachableJar))
		} else if strings.Contains(requestPath, reachableArtifactID) {
			http.ServeFile(w, r, filepath.Join("testdata", reachableJar))
		}
	}, false)
}

func mockClientWithHandler(t *testing.T, handler http.HandlerFunc, closeImmediately bool) *http.Client {
	t.Helper()
	// mock a server to act as Maven Central to avoid network requests.
	server := httptest.NewServer(handler)
	client := server.Client()

	originalURL := java.MavenBaseURL
	java.MavenBaseURL = server.URL

	if closeImmediately {
		server.Close()
	}

	t.Cleanup(func() {
		java.MavenBaseURL = originalURL
		if !closeImmediately {
			server.Close()
		}
	})

	return client
}

func buildResourceOnlyJAR(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	fw, err := zw.Create("META-INF/MANIFEST.MF")
	if err != nil {
		t.Fatalf("zip.Writer.Create() unexpected error: %v", err)
	}
	if _, writeErr := fw.Write([]byte("Manifest-Version: 1.0\n")); writeErr != nil {
		t.Fatalf("manifest Write() unexpected error: %v", writeErr)
	}
	if closeErr := zw.Close(); closeErr != nil {
		t.Fatalf("zip.Writer.Close() unexpected error: %v", closeErr)
	}
	return buf.Bytes()
}

func unreachablePackageIDs(pkgs []*extractor.Package) []string {
	ids := map[string]struct{}{}
	for _, pkg := range pkgs {
		for _, signal := range pkg.ExploitabilitySignals {
			if signal.Justification == vex.VulnerableCodeNotInExecutePath && signal.MatchesAllVulns && signal.Plugin == java.Name {
				ids[pkg.Name+"@"+pkg.Version] = struct{}{}
			}
		}
	}
	if len(ids) == 0 {
		return nil
	}
	return slices.Sorted(maps.Keys(ids))
}

func newMavenPackage(groupID, artifactID, pkgVersion, jarName string) *extractor.Package {
	return &extractor.Package{
		Name:     groupID + ":" + artifactID,
		Version:  pkgVersion,
		PURLType: purl.TypeMaven,
		Metadata: &archivemeta.Metadata{ArtifactID: artifactID, GroupID: groupID},
		Location: extractor.LocationFromPath(filepath.Join("testdata", jarName)),
		Plugins:  []string{archive.Name},
	}
}

func setupPackages(names []string) []*extractor.Package {
	pkgs := []*extractor.Package{}
	for _, n := range names {
		pkgs = append(pkgs,
			newMavenPackage(reachableGroupID, reachableArtifactID, version, n),
			newMavenPackage(unreachableGroupID, unreachableArtifactID, version, n),
		)
	}

	return pkgs
}
