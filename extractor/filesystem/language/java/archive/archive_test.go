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

package archive_test

import (
	"archive/zip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"
)

var (
	errAny = errors.New("any error")
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:         ".jar",
			path:         filepath.FromSlash("some/path/a.jar"),
			wantRequired: true,
		},
		{
			name:         ".JAR",
			path:         filepath.FromSlash("some/path/a.JAR"),
			wantRequired: true,
		},
		{
			name:         ".war",
			path:         filepath.FromSlash("some/path/a.war"),
			wantRequired: true,
		},
		{
			name:         ".ear",
			path:         filepath.FromSlash("some/path/a.ear"),
			wantRequired: true,
		},
		{
			name:         ".jmod",
			path:         filepath.FromSlash("some/path/a.jmod"),
			wantRequired: true,
		},
		{
			name:         ".par",
			path:         filepath.FromSlash("some/path/a.par"),
			wantRequired: true,
		},
		{
			name:         ".sar",
			path:         filepath.FromSlash("some/path/a.sar"),
			wantRequired: true,
		},
		{
			name:         ".jpi",
			path:         filepath.FromSlash("some/path/a.jpi"),
			wantRequired: true,
		},
		{
			name:         ".hpi",
			path:         filepath.FromSlash("some/path/a.hpi"),
			wantRequired: true,
		},
		{
			name:         ".lpkg",
			path:         filepath.FromSlash("some/path/a.lpkg"),
			wantRequired: true,
		},
		{
			name:         ".nar",
			path:         filepath.FromSlash("some/path/a.nar"),
			wantRequired: true,
		},
		{
			name:         "not archive file",
			path:         filepath.FromSlash("some/path/a.txt"),
			wantRequired: false,
		},
		{
			name:         "no extension should be ignored",
			path:         filepath.FromSlash("some/path/a"),
			wantRequired: false,
		},
		{
			name:             ".jar required if size less than maxFileSizeBytes",
			path:             filepath.FromSlash("some/path/a.jar"),
			maxFileSizeBytes: 1000,
			fileSizeBytes:    100,
			wantRequired:     true,
		},
		{
			name:             ".war required if size equal to maxFileSizeBytes",
			path:             filepath.FromSlash("some/path/a.jar"),
			maxFileSizeBytes: 1000,
			fileSizeBytes:    1000,
			wantRequired:     true,
		},
		{
			name:             ".jar not required if size greater than maxFileSizeBytes",
			path:             filepath.FromSlash("some/path/a.jar"),
			maxFileSizeBytes: 100,
			fileSizeBytes:    1000,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
		{
			name:             ".jar required if maxFileSizeBytes explicitly set to 0",
			path:             filepath.FromSlash("some/path/a.jar"),
			maxFileSizeBytes: 0,
			fileSizeBytes:    1000,
			wantRequired:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			cfg := defaultConfigWith(archive.Config{
				MaxFileSizeBytes: tt.maxFileSizeBytes,
				Stats:            collector,
			})

			var e filesystem.Extractor = archive.New(cfg)

			if got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: fs.ModePerm,
				FileSize: tt.fileSizeBytes,
			})); got != tt.wantRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotResultMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && tt.wantResultMetric != gotResultMetric {
				t.Fatalf("FileRequired(%s): recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name             string
		description      string
		cfg              archive.Config
		path             string
		contentPath      string
		want             []*extractor.Inventory
		wantErr          error
		wantResultMetric stats.FileExtractedResult
	}{
		{
			name: "Empty jar file should not return anything",
			path: filepath.FromSlash("testdata/empty.jar"),
		},
		{
			name:    "Not a valid jar file",
			path:    filepath.FromSlash("testdata/not_jar"),
			wantErr: errAny,
		},
		{
			name:    "Invalid jar file",
			path:    filepath.FromSlash("testdata/invalid_jar.jar"),
			wantErr: errAny,
		},
		{
			name:        "Jar file with no pom.properties",
			description: "Contains other files but no pom.properties.",
			path:        filepath.FromSlash("testdata/no_pom_properties.jar"),
			want:        []*extractor.Inventory{},
		},
		{
			name:        "Jar file with invalid pom.properties",
			description: "Contains a pom.properties which is missing the `groupId` field and so it is ignored.",
			path:        filepath.FromSlash("testdata/pom_missing_group_id.jar"),
			want:        []*extractor.Inventory{},
		},
		{
			name: "Jar file with pom.properties",
			path: filepath.FromSlash("testdata/simple.jar"),
			want: []*extractor.Inventory{{
				Name:     "package-name",
				Version:  "1.2.3",
				Metadata: &archive.Metadata{ArtifactID: "package-name", GroupID: "com.some.package"},
				Locations: []string{
					filepath.FromSlash("testdata/simple.jar"),
					filepath.FromSlash("testdata/simple.jar/pom.properties"),
				},
			}},
		},
		{
			name:        "Jar file with no pom.properties, and IdentifyByFilename enabled",
			description: "Contains other files but no pom.properties. Has invalid filename.",
			path:        filepath.FromSlash("testdata/no_pom_properties.jar"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{},
		},
		{
			name:        "Jar file with pom.properties, IdentifyByFilename enabled",
			description: "Contains valid pom.properties, won't be identified by filename.",
			path:        filepath.FromSlash("testdata/simple.jar"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:     "package-name",
				Version:  "1.2.3",
				Metadata: &archive.Metadata{ArtifactID: "package-name", GroupID: "com.some.package"},
				Locations: []string{
					filepath.FromSlash("testdata/simple.jar"),
					filepath.FromSlash("testdata/simple.jar/pom.properties"),
				},
			}},
		},
		{
			name:        "Jar file with no pom.properties and manifest, and IdentifyByFilename enabled",
			description: "Contains other files but no pom.properties and manifest. Has valid filename.",
			path:        filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:     "no_pom_properties",
				Version:  "2.4.0",
				Metadata: &archive.Metadata{ArtifactID: "no_pom_properties", GroupID: "no_pom_properties"},
				Locations: []string{
					filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Jar file with no pom.properties but has manifest, and IdentifyByFilename enabled",
			description: "Contains other files but no pom.properties. Has valid manifest with Group ID. Has valid filename.",
			path:        filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
			contentPath: filepath.FromSlash("testdata/combine-manifest-filename/MANIFEST.MF"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:    "no_pom_properties",
				Version: "2.4.0",
				Metadata: &archive.Metadata{
					ArtifactID: "no_pom_properties",
					GroupID:    "org.apache.ivy", // Group ID overridden by manifest.
				},
				Locations: []string{
					filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Jar file with no pom.properties but has manifest, and IdentifyByFilename enabled",
			description: "Contains other files but no pom.properties. Has valid manifest without Group ID. Has valid filename.",
			path:        filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
			contentPath: filepath.FromSlash("testdata/manifest-no-group-id/MANIFEST.MF"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:    "no_pom_properties",
				Version: "2.4.0",
				Metadata: &archive.Metadata{
					ArtifactID: "no_pom_properties",
					// Group ID defaults to Artifact ID since there was no Group ID in the
					// manifest.
					GroupID: "no_pom_properties",
				},
				Locations: []string{
					filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Jar file with invalid pom.properties and manifest, IdentifyByFilename enabled",
			description: "Contains a pom.properties which is missing the `groupId` field and so it is ignored. Has no manifest. Has valid filename.",
			path:        filepath.FromSlash("testdata/pom_missing_group_id-2.4.0.jar"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:     "pom_missing_group_id",
				Version:  "2.4.0",
				Metadata: &archive.Metadata{ArtifactID: "pom_missing_group_id", GroupID: "pom_missing_group_id"},
				Locations: []string{
					filepath.FromSlash("testdata/pom_missing_group_id-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Jar file with no pom.properties and manifest, and IdentifyByFilename enabled",
			description: "Contains other files but no pom.properties and manifest. Has valid filename with groupID.",
			path:        filepath.FromSlash("testdata/org.eclipse.sisu.inject-0.3.5.jar"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:     "org.eclipse.sisu.inject",
				Version:  "0.3.5",
				Metadata: &archive.Metadata{ArtifactID: "org.eclipse.sisu.inject", GroupID: "org.eclipse.sisu"},
				Locations: []string{
					filepath.FromSlash("testdata/org.eclipse.sisu.inject-0.3.5.jar"),
				},
			}},
		},
		{
			name: "Nested jars with pom.properties at depth 10",
			path: filepath.FromSlash("testdata/nested_at_10.jar"),
			cfg:  archive.Config{HashJars: true},
			want: []*extractor.Inventory{{
				Name:    "package-name",
				Version: "1.2.3",
				Metadata: &archive.Metadata{
					ArtifactID: "package-name",
					GroupID:    "com.some.package",
					SHA1:       "PO6pevcX8f2Rkpv4xB6NYviFokQ=", // inner most nested.jar
				},
				Locations: []string{
					filepath.FromSlash("testdata/nested_at_10.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar"),
					filepath.FromSlash("testdata/nested_at_10.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/nested.jar/pom.properties"),
				},
			}},
		},
		{
			name:        "Nested jars with pom.properties at depth 100",
			description: "Returns error with no results because max depth is reached before getting to pom.properties",
			path:        filepath.FromSlash("testdata/nested_at_100.jar"),
			want:        []*extractor.Inventory{},
			wantErr:     errAny,
		},
		{
			name:        "Jar file with pom.properties at multiple depths",
			description: "A jar file with pom.properties at complex.jar/pom.properties and another at complex.jar/BOOT-INF/lib/inner.jar/pom.properties",
			path:        filepath.FromSlash("testdata/complex.jar"),
			want: []*extractor.Inventory{
				{
					Name:     "package-name",
					Version:  "1.2.3",
					Metadata: &archive.Metadata{ArtifactID: "package-name", GroupID: "com.some.package"},
					Locations: []string{
						filepath.FromSlash("testdata/complex.jar"),
						filepath.FromSlash("testdata/complex.jar/pom.properties"),
					},
				},
				{
					Name:     "another-package-name",
					Version:  "3.2.1",
					Metadata: &archive.Metadata{ArtifactID: "another-package-name", GroupID: "com.some.anotherpackage"},
					Locations: []string{
						filepath.FromSlash("testdata/complex.jar"),
						filepath.FromSlash("testdata/complex.jar/BOOT-INF/lib/inner.jar"),
						filepath.FromSlash("testdata/complex.jar/BOOT-INF/lib/inner.jar/pom.properties"),
					},
				},
			},
		},
		{
			name:        "Ignore inner pom.properties because max opened bytes reached",
			description: "A jar file with pom.properties at complex.jar/pom.properties and another at complex.jar/BOOT-INF/lib/inner.jar/pom.properties. The inner pom.properties is never extracted because MaxOpenedBytes is reached.",
			cfg: archive.Config{
				MaxOpenedBytes: 700,
				Stats:          testcollector.New(),
			},
			path: filepath.FromSlash("testdata/complex.jar"),
			want: []*extractor.Inventory{{
				Name:     "package-name",
				Version:  "1.2.3",
				Metadata: &archive.Metadata{ArtifactID: "package-name", GroupID: "com.some.package"},
				Locations: []string{
					filepath.FromSlash("testdata/complex.jar"),
					filepath.FromSlash("testdata/complex.jar/pom.properties"),
				},
			}},
			wantErr:          filesystem.ErrExtractorMemoryLimitExceeded,
			wantResultMetric: stats.FileExtractedResultErrorMemoryLimitExceeded,
		},
		{
			name: "Realistic jar file with pom.properties",
			path: filepath.FromSlash("testdata/guava-31.1-jre.jar"),
			cfg:  archive.Config{HashJars: true},
			want: []*extractor.Inventory{
				{
					Name:    "guava",
					Version: "31.1-jre",
					Metadata: &archive.Metadata{
						ArtifactID: "guava",
						GroupID:    "com.google.guava",
						// openssl sha1 -binary third_party/scalibr/extractor/filesystem/language/java/archive/testdata/guava-31.1-jre.jar | base64
						SHA1: "YEWPh30FXQyRFNnhou+3N7S8KCw=",
					},
					Locations: []string{
						filepath.FromSlash("testdata/guava-31.1-jre.jar"),
						filepath.FromSlash("testdata/guava-31.1-jre.jar/META-INF/maven/com.google.guava/guava/pom.properties"),
					},
				},
			},
		},
		{
			name: "Test MANIFEST.MF with no valid ArtifactID",
			path: filepath.FromSlash("testdata/com.google.src.yolo-0.1.2.jar"),
			want: []*extractor.Inventory{},
		},
		{
			name:        "Test MANIFEST.MF with symbolic name",
			path:        filepath.FromSlash("testdata/manifest-symbolicname"),
			contentPath: filepath.FromSlash("testdata/manifest-symbolicname/MANIFEST.MF"),
			want: []*extractor.Inventory{{
				Name:    "failureaccess",
				Version: "1.0.1",
				Metadata: &archive.Metadata{
					ArtifactID: "failureaccess",
					GroupID:    "com.google.guava.failureaccess",
				},
				Locations: []string{
					filepath.FromSlash("testdata/manifest-symbolicname"),
					filepath.FromSlash("testdata/manifest-symbolicname/MANIFEST.MF"),
				},
			}},
		},
		{
			name:        "Test invalid group or artifact id in manifest.mf",
			path:        filepath.FromSlash("testdata/invalid-ids"),
			contentPath: filepath.FromSlash("testdata/invalid-ids/MANIFEST.MF"),
			want: []*extractor.Inventory{{
				Name:    "correct.name",
				Version: "1.2.3",
				Metadata: &archive.Metadata{
					ArtifactID: "correct.name",
					GroupID:    "test.group",
				},
				Locations: []string{
					filepath.FromSlash("testdata/invalid-ids"),
					filepath.FromSlash("testdata/invalid-ids/MANIFEST.MF"),
				},
			}},
		},
		{
			name:        "Test artifact ID that is mapped to a known group ID",
			path:        filepath.FromSlash("testdata/known-group-id"),
			contentPath: filepath.FromSlash("testdata/known-group-id/MANIFEST.MF"),
			want: []*extractor.Inventory{{
				Name:    "spring-web",
				Version: "5.3.26",
				Metadata: &archive.Metadata{
					ArtifactID: "spring-web",
					GroupID:    "org.springframework",
				},
				Locations: []string{
					filepath.FromSlash("testdata/known-group-id"),
					filepath.FromSlash("testdata/known-group-id/MANIFEST.MF"),
				},
			}},
		},
		{
			name:        "Test combination of manifest and filename",
			path:        filepath.FromSlash("testdata/ivy-2.4.0.jar"),
			contentPath: filepath.FromSlash("testdata/combine-manifest-filename/MANIFEST.MF"),
			cfg:         archive.Config{ExtractFromFilename: true},
			want: []*extractor.Inventory{{
				Name:    "ivy",
				Version: "2.4.0",
				Metadata: &archive.Metadata{
					ArtifactID: "ivy",
					GroupID:    "org.apache.ivy",
				},
				Locations: []string{
					filepath.FromSlash("testdata/ivy-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Test combination of filename and manifest with group ID transform",
			description: "The manifest has a Implementation-Title field with more data than just the group ID and we want to extract just the group ID.",
			path:        filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
			contentPath: filepath.FromSlash("testdata/manifest-implementation-title/MANIFEST.MF"),
			cfg:         archive.Config{ExtractFromFilename: true},
			want: []*extractor.Inventory{{
				Name:    "no_pom_properties",
				Version: "2.4.0",
				Metadata: &archive.Metadata{
					ArtifactID: "no_pom_properties",
					GroupID:    "org.elasticsearch",
				},
				Locations: []string{
					filepath.FromSlash("testdata/no_pom_properties-2.4.0.jar"),
				},
			}},
		},
		{
			name:        "Apache Axis package with incorrect artifact and group ID and space in version",
			description: "The MANIFEST.MF file has 4 main issues: 1) The Name field is `org/apache/axis` which is incorrect. 2) The Implementation-Title field is `Apache Axis` which is incorrect. 3) The Implementation-Version field is has spaces `1.4 1855 April 22 2006`. 4) There is a blank new line in the file.",
			path:        filepath.FromSlash("testdata/axis"),
			contentPath: filepath.FromSlash("testdata/axis/MANIFEST.MF"),
			cfg: archive.Config{
				ExtractFromFilename: true,
			},
			want: []*extractor.Inventory{{
				Name:     "axis",
				Version:  "1.4",
				Metadata: &archive.Metadata{ArtifactID: "axis", GroupID: "org.apache.axis"},
				Locations: []string{
					filepath.FromSlash("testdata/axis"),
					filepath.FromSlash("testdata/axis/MANIFEST.MF"),
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var f *os.File
			var err error
			if tt.contentPath != "" {
				f = mustJar(t, tt.contentPath)
			} else {
				f, err = os.Open(tt.path)
				if err != nil {
					t.Fatalf("os.Open(%s) unexpected error: %v", tt.path, err)
				}
			}
			defer f.Close()

			info, err := f.Stat()
			if err != nil {
				t.Fatalf("f.Stat() for %q unexpected error: %v", tt.path, err)
			}

			// os.Open returns a ReaderAt per default. In case MaxOpenedBytes is set, we want to have no
			// ReaderAt, such that we can test the MaxOpenedBytes limit.
			var r io.Reader = f
			if tt.cfg.MaxOpenedBytes > 0 {
				r = noReaderAt{r: r}
			}

			collector := testcollector.New()
			tt.cfg.Stats = collector

			input := &filesystem.ScanInput{FS: scalibrfs.DirFS("."), Path: tt.path, Info: info, Reader: r}

			log.SetLogger(&log.DefaultLogger{Verbose: true})
			e := archive.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), input)
			if err != nil && tt.wantErr == errAny {
				err = errAny
			}
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("Extract(%s) got error: %v, want error: %v", tt.path, err, tt.wantErr)
			}
			sort := func(a, b *extractor.Inventory) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(sort)); diff != "" {
				t.Fatalf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}

			gotResultMetric := collector.FileExtractedResult(tt.path)
			if tt.wantResultMetric != "" && tt.wantResultMetric != gotResultMetric {
				t.Fatalf("Extract(%s): recorded result metric %v, want result metric %v", tt.path, gotResultMetric, tt.wantResultMetric)
			}

			gotFileSizeMetric := collector.FileExtractedFileSize(tt.path)
			if gotFileSizeMetric != info.Size() {
				t.Errorf("Extract(%s) recorded file size %v, want file size %v", tt.path, gotFileSizeMetric, info.Size())
			}
		})
	}
}

func TestToPURL(t *testing.T) {
	e := archive.Extractor{}
	i := &extractor.Inventory{
		Name:    "Name",
		Version: "1.2.3",
		Metadata: &archive.Metadata{
			ArtifactID: "ArtifactID",
			GroupID:    "GroupID",
		},
		Locations: []string{"location"},
	}
	want := &purl.PackageURL{
		Type:      purl.TypeMaven,
		Name:      "artifactid",
		Namespace: "groupid",
		Version:   "1.2.3",
	}
	got := e.ToPURL(i)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("ToPURL(%v) (-want +got):\n%s", i, diff)
	}
}

type noReaderAt struct {
	r io.Reader
}

func (r noReaderAt) Read(p []byte) (n int, err error) {
	return r.r.Read(p)
}

// defaultConfigWith combines any non-zero fields of cfg with archive.DefaultConfig().
func defaultConfigWith(cfg archive.Config) archive.Config {
	newCfg := archive.DefaultConfig()

	if cfg.MaxZipDepth > 0 {
		newCfg.MaxZipDepth = cfg.MaxZipDepth
	}
	if cfg.MaxOpenedBytes > 0 {
		newCfg.MaxOpenedBytes = cfg.MaxOpenedBytes
	}
	if cfg.MinZipBytes > 0 {
		newCfg.MinZipBytes = cfg.MinZipBytes
	}
	if cfg.MaxFileSizeBytes > 0 {
		newCfg.MaxFileSizeBytes = cfg.MaxFileSizeBytes
	}
	if cfg.Stats != nil {
		newCfg.Stats = cfg.Stats
	}
	// ignores defaults
	newCfg.ExtractFromFilename = cfg.ExtractFromFilename
	newCfg.HashJars = cfg.HashJars
	return newCfg
}

// mustJar creates a temporary jar file that contains the file from path and returns it opened.
func mustJar(t *testing.T, path string) *os.File {
	t.Helper()

	dir := filepath.Dir(path)
	dirEntry, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s) unexpected error: %v", path, err)
	}
	fmt.Printf("%+v", dirEntry)
	dir = filepath.Dir(path)
	dirEntry, err = os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%s) unexpected error: %v", path, err)
	}
	fmt.Printf("%+v", dirEntry)

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("os.Open(%s) unexpected error: %v", path, err)
	}
	defer f.Close()

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("os.ReadFile(%s) unexpected error: %v", path, err)
	}

	jarFile, err := os.CreateTemp("", "temp-*.jar")
	if err != nil {
		t.Fatalf("os.CreateTemp(\"temp-*.jar\") unexpected error: %v", err)
	}
	defer jarFile.Sync()

	zipWriter := zip.NewWriter(jarFile)

	fileWriter, err := zipWriter.Create(filepath.Base(path))
	if err != nil {
		t.Fatalf("zipWriter.Create(%s) unexpected error: %v", filepath.Base(path), err)
	}
	_, err = fileWriter.Write(content)
	if err != nil {
		t.Fatalf("fileWriter.Write(%s) unexpected error: %v", filepath.Base(path), err)
	}

	err = zipWriter.Close()
	if err != nil {
		t.Fatalf("zipWriter.Close() unexpected error: %v", err)
	}

	return jarFile
}
