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

package condaenv_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condaenv"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/location"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{
			name: "environment_yml_at_repo_root",
			path: "environment.yml",
			want: true,
		},
		{
			name: "environment_yaml_at_repo_root",
			path: "environment.yaml",
			want: true,
		},
		{
			name: "environment_yml_in_subdirectory",
			path: "src/ml/environment.yml",
			want: true,
		},
		{
			name: "environment_yml_in_absolute_style_path",
			path: "home/user/proj/environment.yml",
			want: true,
		},
		{
			name: "file_name_only_ends_with_environment_yml",
			path: "conda-environment.yml",
			want: false,
		},
		{
			name: "directory_named_environment_yml",
			path: "environment.yml/config.yaml",
			want: false,
		},
		{
			name: "environment_file_without_yaml_extension",
			path: "environment",
			want: false,
		},
		{
			name: "conda_lock_file",
			path: "conda-lock.yml",
			want: false,
		},
		{
			name: "unrelated_yaml_file",
			path: "config/app.yml",
			want: false,
		},
		{
			name: "conda_meta_json_of_an_installed_environment",
			path: "envs/ml/conda-meta/scipy-1.9.0-py310.json",
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			extr, err := condaenv.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("condaenv.New() error: %v", err)
			}
			fi := fakefs.FakeFileInfo{FileName: tc.path, FileSize: 1024}
			got := extr.FileRequired(simplefileapi.New(tc.path, fi))
			if got != tc.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tc.path, got, tc.want)
			}
		})
	}
}

func TestFileRequired_FileSizeLimit(t *testing.T) {
	extr, err := condaenv.New(&cpb.PluginConfig{MaxFileSizeBytes: 100})
	if err != nil {
		t.Fatalf("condaenv.New() error: %v", err)
	}
	path := "environment.yml"
	fi := fakefs.FakeFileInfo{FileName: path, FileSize: 200}
	if extr.FileRequired(simplefileapi.New(path, fi)) {
		t.Errorf("FileRequired(%q) = true, want false (over size limit)", path)
	}
}

func loc(path string, line int) extractor.PackageLocation {
	return extractor.PackageLocation{
		Descriptor: &location.Location{
			File: &location.File{
				Path:       path,
				LineNumber: line,
			},
		},
	}
}

func pypiPackage(name, version, path string, line int) *extractor.Package {
	return &extractor.Package{
		Name:     name,
		Version:  version,
		PURLType: purl.TypePyPi,
		Location: loc(path, line),
	}
}

func TestExtract(t *testing.T) {
	tests := []extracttest.TestTableEntry{
		{
			Name:        "pinned_conda_dependencies_and_pip_subsection",
			InputConfig: extracttest.ScanInputMockConfig{Path: "testdata/valid.yml"},
			WantPackages: []*extractor.Package{
				pypiPackage("scipy", "1.9.0", "testdata/valid.yml", 7),
				pypiPackage("numpy", "1.23.0", "testdata/valid.yml", 8),
				pypiPackage("pandas", "1.5.3", "testdata/valid.yml", 9),
				pypiPackage("cryptography", "38.0.0", "testdata/valid.yml", 10),
				pypiPackage("tensorflow", "2.10.0", "testdata/valid.yml", 13),
				pypiPackage("torch", "1.13.0", "testdata/valid.yml", 14),
				pypiPackage("requests", "2.28.1", "testdata/valid.yml", 15),
				pypiPackage("celery", "5.2.7", "testdata/valid.yml", 16),
			},
		},
		{
			Name:        "wildcard_versions_report_the_version_series",
			InputConfig: extracttest.ScanInputMockConfig{Path: "testdata/wildcards.yml"},
			WantPackages: []*extractor.Package{
				pypiPackage("numpy", "1.26", "testdata/wildcards.yml", 3),
				pypiPackage("scipy", "1", "testdata/wildcards.yml", 4),
				pypiPackage("torch", "2.0", "testdata/wildcards.yml", 7),
			},
		},
		{
			Name:         "ranges_options_and_direct_references_are_skipped",
			InputConfig:  extracttest.ScanInputMockConfig{Path: "testdata/unpinned.yaml"},
			WantPackages: nil,
		},
		{
			Name:         "no_dependencies_section",
			InputConfig:  extracttest.ScanInputMockConfig{Path: "testdata/no-dependencies.yml"},
			WantPackages: nil,
		},
		{
			Name:         "dependencies_is_a_map_not_a_list",
			InputConfig:  extracttest.ScanInputMockConfig{Path: "testdata/dependencies-not-a-list.yml"},
			WantPackages: nil,
		},
		{
			Name:         "pip_subsection_is_a_map_and_unknown_subsections",
			InputConfig:  extracttest.ScanInputMockConfig{Path: "testdata/odd-subsections.yml"},
			WantPackages: nil,
		},
		{
			Name:         "empty_file",
			InputConfig:  extracttest.ScanInputMockConfig{Path: "testdata/empty.yml"},
			WantPackages: nil,
		},
		{
			Name:        "invalid_yaml",
			InputConfig: extracttest.ScanInputMockConfig{Path: "testdata/invalid.yml"},
			WantErr:     extracttest.ContainsErrStr{Str: "failed to parse YAML"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr, err := condaenv.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatalf("condaenv.New() error: %v", err)
			}
			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(t.Context(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			wantInv := inventory.Inventory{Packages: tt.WantPackages}
			if diff := cmp.Diff(wantInv, got, cmpopts.SortSlices(extracttest.PackageCmpLess)); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}

func TestExtract_PURLAndEcosystem(t *testing.T) {
	extr, err := condaenv.New(&cpb.PluginConfig{})
	if err != nil {
		t.Fatalf("condaenv.New() error: %v", err)
	}
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: "testdata/valid.yml",
	})
	defer extracttest.CloseTestScanInput(t, input)

	inv, err := extr.Extract(t.Context(), &input)
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(inv.Packages) == 0 {
		t.Fatalf("Extract returned no packages")
	}

	var scipy *extractor.Package
	for _, pkg := range inv.Packages {
		if pkg.Name == "scipy" {
			scipy = pkg
			break
		}
	}
	if scipy == nil {
		t.Fatalf("Extract didn't report the scipy package")
	}
	if got, want := scipy.PURL().String(), "pkg:pypi/scipy@1.9.0"; got != want {
		t.Errorf("PURL = %q, want %q", got, want)
	}
	if got, want := scipy.Ecosystem().String(), "PyPI"; got != want {
		t.Errorf("Ecosystem = %q, want %q", got, want)
	}
}
