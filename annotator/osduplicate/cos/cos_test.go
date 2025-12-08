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

package cos_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate/cos"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"google.golang.org/protobuf/proto"
)

const (
	cosPackageInfoFile = "etc/cos-package-info.json"
)

func TestAnnotate(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		desc string
		// If nil, a default COS filesystem will be used.
		input    *annotator.ScanInput
		packages []*extractor.Package
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc: "some_pkgs_found_in_cos_pkg_folder",
			packages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
				},
				{
					Name:      "file-not-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/file/not/in/pkgs"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          cos.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:      "file-not-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/file/not/in/pkgs"},
				},
			},
		},
		{
			desc: "some_pkgs_outside_mutable_dir",
			packages: []*extractor.Package{
				{
					Name:      "file-in-mutable-dir",
					Locations: []string{"mnt/stateful_partition/in/mutable/dir"},
				},
				{
					Name:      "file-not-in-mutable-dir",
					Locations: []string{"not/in/mutable/dir"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file-in-mutable-dir",
					Locations: []string{"mnt/stateful_partition/in/mutable/dir"},
				},
				{
					Name:      "file-not-in-mutable-dir",
					Locations: []string{"not/in/mutable/dir"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          cos.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
			},
		},
		{
			desc: "pkgs_found_in_non_cos_filesystem",
			input: &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(t.TempDir()),
			},
			packages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
				},
				{
					Name:      "file-not-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/file/not/in/pkgs"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
					// Expect no exploitability signals.
				},
				{
					Name:      "file-not-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/file/not/in/pkgs"},
				},
			},
		},
		{
			desc:         "pkg_has_no_location",
			packages:     []*extractor.Package{{Name: "file"}},
			wantPackages: []*extractor.Package{{Name: "file"}},
		},
		{
			desc: "ctx_cancelled",
			ctx:  cancelledContext,
			packages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file-in-cos-pkgs",
					Locations: []string{"mnt/stateful_partition/var_overlay/db/pkg/path/to/file-in-cos-pkgs"},
					// No exploitability signals
				},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context()
			}
			input := tt.input
			if input == nil {
				input = &annotator.ScanInput{
					ScanRoot: mustCOSFS(t),
				}
			}

			// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := cos.New().Annotate(tt.ctx, input, inv)
			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Annotate(%v) error: %v, want %v", tt.packages, err, tt.wantErr)
			}

			want := &inventory.Inventory{Packages: tt.wantPackages}
			if diff := cmp.Diff(want, inv); diff != "" {
				t.Errorf("Annotate(%v): unexpected diff (-want +got): %v", tt.packages, diff)
			}
		})
	}
}

// mustWriteFiles creates all directories and writes all files in the given map.
func mustWriteFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for path, content := range files {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatalf("Failed to create directory %s: %v", filepath.Dir(path), err)
		}
		if err := os.WriteFile(path, []byte(content), 0644); err != nil {
			t.Fatalf("Failed to write file %s: %v", path, err)
		}
	}
}

// mustCOSFS returns a ScanRoot representing a COS filesystem with the package info file.
func mustCOSFS(t *testing.T) *scalibrfs.ScanRoot {
	t.Helper()
	dir := t.TempDir()
	files := map[string]string{
		filepath.Join(dir, cosPackageInfoFile): "",
	}
	mustWriteFiles(t, files)
	return scalibrfs.RealFSScanRoot(dir)
}
