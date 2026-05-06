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
	"io/fs"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
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

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name: "valid_jpi_with_short_name_and_version",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid-git.jpi",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.jenkins-ci.plugins:git",
					Version:  "5.2.1",
					PURLType: purl.TypeMaven,
					Metadata: &archivemeta.Metadata{
						GroupID:    "org.jenkins-ci.plugins",
						ArtifactID: "git",
					},
					Location: extractor.LocationFromPath("testdata/valid-git.jpi"),
				},
			},
		},
		{
			// workflow-job has Group-Id: org.jenkins-ci.plugins.workflow in its manifest,
			// so the PURL namespace and Package.Name must use that group.
			Name: "valid_hpi_uses_manifest_group_id",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/valid-workflow-job.hpi",
			},
			WantPackages: []*extractor.Package{
				{
					Name:     "org.jenkins-ci.plugins.workflow:workflow-job",
					Version:  "1385.vb_58b_86ea_fff1",
					PURLType: purl.TypeMaven,
					Metadata: &archivemeta.Metadata{
						GroupID:    "org.jenkins-ci.plugins.workflow",
						ArtifactID: "workflow-job",
					},
					Location: extractor.LocationFromPath("testdata/valid-workflow-job.hpi"),
				},
			},
		},
		{
			// Short-Name is written unconditionally by maven-hpi-plugin; a manifest
			// without it is malformed — emit nothing.
			Name: "missing_short_name_emits_nothing",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-short-name.jpi",
			},
			WantPackages: nil,
		},
		{
			// Group-Id is required; a manifest without it is malformed — emit nothing.
			Name: "missing_group_id_emits_nothing",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-group-id.jpi",
			},
			WantPackages: nil,
		},
		{
			// Version is required; a manifest without it is malformed — emit nothing.
			Name: "missing_plugin_version_emits_nothing",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/missing-version.jpi",
			},
			WantPackages: nil,
		},
		{
			// A JPI zip without a manifest is malformed — emit nothing.
			Name: "zip_without_manifest_emits_nothing",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/no-manifest.jpi",
			},
			WantPackages: nil,
		},
		{
			// A JPI non-ZIP file is malformed — emit nothing.
			Name: "invalid_zip_emits_nothing",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/invalid-not-zip.jpi",
			},
			WantPackages: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			e, err := plugins.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("plugins.New() failed: %v", err)
			}

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := e.Extract(t.Context(), &scanInput)

			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
				return
			}

			want := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(want, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", e.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
