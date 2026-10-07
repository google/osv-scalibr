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

package plugins_test

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/jenkins/plugins"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/stats"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
	"github.com/google/osv-scalibr/testing/testcollector"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name             string
		path             string
		fileMode         fs.FileMode
		fileSizeBytes    int64
		maxFileSizeBytes int64
		wantRequired     bool
		wantResultMetric stats.FileRequiredResult
	}{
		{
			name:             "jpi_file",
			path:             "var/lib/jenkins/plugins/git.jpi",
			fileMode:         fs.ModePerm,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "hpi_file",
			path:             "var/jenkins_home/plugins/workflow-job.hpi",
			fileMode:         fs.ModePerm,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "uppercase_JPI",
			path:             "plugins/foo.JPI",
			fileMode:         fs.ModePerm,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:         "jar_file_not_required",
			path:         "plugins/foo.jar",
			fileMode:     fs.ModePerm,
			wantRequired: false,
		},
		{
			name:         "php_file_not_required",
			path:         "plugins/foo.php",
			fileMode:     fs.ModePerm,
			wantRequired: false,
		},
		{
			name:         "directory_not_required",
			path:         "plugins/git.jpi",
			fileMode:     fs.ModeDir,
			wantRequired: false,
		},
		{
			name:             "file_size_under_max",
			path:             "plugins/git.jpi",
			fileMode:         fs.ModePerm,
			fileSizeBytes:    100,
			maxFileSizeBytes: 1000,
			wantRequired:     true,
			wantResultMetric: stats.FileRequiredResultOK,
		},
		{
			name:             "file_size_exceeds_max",
			path:             "plugins/git.jpi",
			fileMode:         fs.ModePerm,
			fileSizeBytes:    2000,
			maxFileSizeBytes: 1000,
			wantRequired:     false,
			wantResultMetric: stats.FileRequiredResultSizeLimitExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector := testcollector.New()
			e, err := plugins.New(&cpb.PluginConfig{MaxFileSizeBytes: tt.maxFileSizeBytes})
			if err != nil {
				t.Fatalf("plugins.New() failed: %v", err)
			}
			e.(*plugins.Extractor).Stats = collector

			fileSizeBytes := tt.fileSizeBytes
			if fileSizeBytes == 0 {
				fileSizeBytes = 1000
			}

			got := e.FileRequired(simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: filepath.Base(tt.path),
				FileMode: tt.fileMode,
				FileSize: fileSizeBytes,
			}))
			if got != tt.wantRequired {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.wantRequired)
			}

			gotMetric := collector.FileRequiredResult(tt.path)
			if tt.wantResultMetric != "" && gotMetric != tt.wantResultMetric {
				t.Errorf("FileRequired(%q) metric = %v, want %v", tt.path, gotMetric, tt.wantResultMetric)
			}
		})
	}
}

// makeJPI builds an in-memory Jenkins plugin (ZIP) archive. If manifest is
// non-empty it is stored as META-INF/MANIFEST.MF.
func makeJPI(t *testing.T, manifest string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if manifest != "" {
		w, err := zw.Create("META-INF/MANIFEST.MF")
		if err != nil {
			t.Fatalf("zip.Create(): %v", err)
		}
		if _, err := w.Write([]byte(manifest)); err != nil {
			t.Fatalf("zip.Write(): %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zip.Close(): %v", err)
	}
	return buf.Bytes()
}

func jenkinsPackage(path, groupID, artifactID, version string) *extractor.Package {
	return &extractor.Package{
		Name:     groupID + ":" + artifactID,
		Version:  version,
		PURLType: purl.TypeMaven,
		Metadata: &archivemeta.Metadata{
			GroupID:    groupID,
			ArtifactID: artifactID,
		},
		Location: extractor.LocationFromPath(path),
	}
}

func TestExtract(t *testing.T) {
	const path = "var/lib/jenkins/plugins/plugin.jpi"

	tests := []struct {
		name         string
		data         []byte
		wantPackages []*extractor.Package
	}{
		{
			name: "valid_jpi",
			data: makeJPI(t, "Manifest-Version: 1.0\r\n"+
				"Short-Name: git\r\n"+
				"Long-Name: Git plugin\r\n"+
				"Plugin-Version: 5.2.1\r\n"+
				"Group-Id: org.jenkins-ci.plugins\r\n"+
				"Jenkins-Version: 2.387.3\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins", "git", "5.2.1"),
			},
		},
		{
			name: "uses_manifest_group_id",
			data: makeJPI(t, "Manifest-Version: 1.0\r\n"+
				"Short-Name: workflow-job\r\n"+
				"Plugin-Version: 1385.vb_58b_86ea_fff1\r\n"+
				"Group-Id: org.jenkins-ci.plugins.workflow\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins.workflow", "workflow-job", "1385.vb_58b_86ea_fff1"),
			},
		},
		{
			name: "manifest_without_trailing_blank_line",
			data: makeJPI(t, "Short-Name: git\nPlugin-Version: 5.2.1\nGroup-Id: org.jenkins-ci.plugins"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins", "git", "5.2.1"),
			},
		},
		{
			name: "snapshot_version_build_description_stripped",
			data: makeJPI(t, "Short-Name: my-plugin\r\n"+
				"Plugin-Version: 1.0-SNAPSHOT (private-10/06/2026 12:00-jenkins)\r\n"+
				"Group-Id: io.jenkins.plugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "io.jenkins.plugins", "my-plugin", "1.0-SNAPSHOT"),
			},
		},
		{
			name: "wrapped_manifest_lines_are_joined",
			data: makeJPI(t, "Short-Name: some-very-long-plugin-name-that-needs-to-be-wrapped-at-seve\r\n"+
				" nty-two-bytes\r\n"+
				"Plugin-Version: 2.0\r\n"+
				"Group-Id: io.jenkins.pl\r\n"+
				" ugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "io.jenkins.plugins", "some-very-long-plugin-name-that-needs-to-be-wrapped-at-seventy-two-bytes", "2.0"),
			},
		},
		{
			name: "group_id_and_short_name_lowercased",
			data: makeJPI(t, "Short-Name: My-Plugin\r\n"+
				"Plugin-Version: 1.0\r\n"+
				"Group-Id: IO.Jenkins.Plugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "io.jenkins.plugins", "my-plugin", "1.0"),
			},
		},
		{
			name: "missing_group_id_falls_back_to_implementation_vendor_id",
			data: makeJPI(t, "Short-Name: legacy-plugin\r\n"+
				"Plugin-Version: 3.1.0\r\n"+
				"Implementation-Vendor-Id: org.jvnet.hudson.plugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jvnet.hudson.plugins", "legacy-plugin", "3.1.0"),
			},
		},
		{
			name: "missing_group_id_falls_back_to_default",
			data: makeJPI(t, "Short-Name: legacy-plugin\r\n"+
				"Plugin-Version: 3.1.0\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins", "legacy-plugin", "3.1.0"),
			},
		},
		{
			name: "missing_short_name_falls_back_to_extension_name",
			data: makeJPI(t, "Extension-Name: legacy-plugin\r\n"+
				"Plugin-Version: 1.0.0\r\n"+
				"Group-Id: org.jenkins-ci.plugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins", "legacy-plugin", "1.0.0"),
			},
		},
		{
			name: "missing_plugin_version_falls_back_to_implementation_version",
			data: makeJPI(t, "Short-Name: legacy-plugin\r\n"+
				"Implementation-Version: 1.2\r\n"+
				"Group-Id: org.jenkins-ci.plugins\r\n\r\n"),
			wantPackages: []*extractor.Package{
				jenkinsPackage(path, "org.jenkins-ci.plugins", "legacy-plugin", "1.2"),
			},
		},
		{
			name: "missing_short_name_emits_nothing",
			data: makeJPI(t, "Long-Name: Some Plugin\r\n"+
				"Plugin-Version: 1.0.0\r\n"+
				"Group-Id: org.jenkins-ci.plugins\r\n\r\n"),
		},
		{
			name: "missing_version_emits_nothing",
			data: makeJPI(t, "Short-Name: some-plugin\r\n"+
				"Group-Id: org.jenkins-ci.plugins\r\n\r\n"),
		},
		{
			name: "zip_without_manifest_emits_nothing",
			data: makeJPI(t, ""),
		},
		{
			name: "invalid_zip_emits_nothing",
			data: []byte("not a zip file"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, err := plugins.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("plugins.New() failed: %v", err)
			}

			input := &filesystem.ScanInput{
				Path:   path,
				Reader: bytes.NewReader(tt.data),
				Info: fakefs.FakeFileInfo{
					FileName: filepath.Base(path),
					FileMode: fs.ModePerm,
					FileSize: int64(len(tt.data)),
				},
			}

			got, err := e.Extract(t.Context(), input)
			if err != nil {
				t.Fatalf("%s.Extract(%q) unexpected error: %v", e.Name(), tt.name, err)
			}

			want := inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.name, diff)
			}
		})
	}
}
