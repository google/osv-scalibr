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

package dpkg_test

import (
	"context"
	"io/fs"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate/dpkg"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"golang.org/x/tools/txtar"
	"google.golang.org/protobuf/proto"
)

type scalibrAdapter struct {
	fs.FS
}

func (a scalibrAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	return fs.ReadDir(a.FS, name)
}
func (a scalibrAdapter) Stat(name string) (fs.FileInfo, error) {
	return fs.Stat(a.FS, name)
}

func TestAnnotate(t *testing.T) {
	// TODO: de-comment this
	// if runtime.GOOS != "linux" {
	// 	t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	// }

	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		desc     string
		packages []*extractor.Package
		txt      string
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc: "missing_info_dir",
			txt:  ``,
		},
		{
			desc: "empty_info_dir",
			txt: `
-- var/lib/dpkg/info/.keep --
			`,
			packages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
				},
			},
		},
		{
			desc: "some_pkgs_found_in_info",
			txt: `
-- var/lib/dpkg/info/some.list --
/some/path
/path/to/file-in-info
/some/other/path
-- var/lib/dpkg/info/some.other.list --
/some/other/path
`,
			packages: []*extractor.Package{
				{
					Name:      "file-in-info",
					Locations: []string{"path/to/file-in-info"},
				},
				{
					Name:      "file-not-in-info",
					Locations: []string{"path/to/file-not-in-info"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file-in-info",
					Locations: []string{"path/to/file-in-info"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{{
						Plugin:          dpkg.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:      "file-not-in-info",
					Locations: []string{"path/to/file-not-in-info"},
				},
			},
		},
		{
			desc: "pkg_found_in_file_with_wrong_extension",
			txt: `
-- var/lib/dpkg/info/some.notlist --
/path/to/file
`,
			packages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
					// No exploitability signals
				},
			},
		},
		{
			desc: "pkg_has_no_location",
			txt: `
-- var/lib/dpkg/info/some.list --
/path/to/file
`,
			packages:     []*extractor.Package{{Name: "file"}},
			wantPackages: []*extractor.Package{{Name: "file"}},
		},
		{
			desc: "ctx_cancelled",
			ctx:  cancelledContext,
			txt: `
-- var/lib/dpkg/info/some.list --
/path/to/file
`,
			packages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "file",
					Locations: []string{"path/to/file"},
					// No exploitability signals
				},
			},
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			// Parse from memory instead of ParseFile
			archive := txtar.Parse([]byte(tt.txt))
			mfs, err := txtar.FS(archive)
			if err != nil {
				t.Fatal(err)
			}
			input := &annotator.ScanInput{
				ScanRoot: &scalibrfs.ScanRoot{
					FS: scalibrAdapter{FS: mfs},
				},
			}

			// Ensure context is never nil (default to test context)
			ctx := tt.ctx
			if ctx == nil {
				ctx = t.Context()
			}

			// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			anno, err := dpkg.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatal(err)
			}

			err = anno.Annotate(ctx, input, inv)
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
