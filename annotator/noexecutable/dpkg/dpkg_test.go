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

package dpkg_test

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/noexecutable/dpkg"
	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"google.golang.org/protobuf/proto"
)

// Sets up the DPKG info directory based on the supplied filename->content map.
// also create the provided files, making them binary if no extension is provides
func setupDPKGInfo(t *testing.T, contents map[string]string) string {
	t.Helper()

	dir := t.TempDir()

	infoDir := filepath.Join(dir, "var/lib/dpkg/info")
	if err := os.MkdirAll(infoDir, 0777); err != nil {
		t.Fatalf("error creating directory %q: %v", infoDir, err)
	}

	for name, content := range contents {
		listPath := filepath.Join(infoDir, name)

		listFile, err := os.Create(listPath)
		if err != nil {
			t.Fatalf("Error while creating file %q: %v", listPath, err)
		}

		for path := range strings.SplitSeq(content, "\n") {
			path, isFolder := strings.CutSuffix(path, "/")

			if _, err := listFile.WriteString(path + "\n"); err != nil {
				t.Fatalf("Error writing creating file %q: %v", listPath, err)
			}

			fullPath := filepath.Join(dir, path)

			if isFolder {
				if err := os.Mkdir(fullPath, 0777); err != nil {
					t.Fatalf("Error creating directory %q: %v", infoDir, err)
				}
				continue
			}
			perm := os.FileMode(0666)
			if !strings.Contains(fullPath, ".") {
				perm = 0755
			}
			if err := os.WriteFile(fullPath, []byte{}, perm); err != nil {
				t.Fatalf("Error creating file %q: %v", fullPath, err)
			}
		}
	}
	return dir
}

func TestAnnotate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		desc     string
		packages []*extractor.Package
		// the .list file content has been modified adding a trailing "/" at
		// the end of each folder to simplify the setupDPKGInfo logic
		infoContents map[string]string
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc:         "missing_info_dir",
			infoContents: nil,
			wantErr:      cmpopts.AnyError,
		},
		{
			desc:         "empty_info_dir",
			infoContents: map[string]string{},
			packages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantPackages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "ctx_cancelled",
			ctx:  cancelledContext,
			infoContents: map[string]string{
				"curl.list": "/usr/\n/usr/bin/\n/usr/bin/curl\n/usr/share/\n/usr/share/doc/\n/usr/share/doc/curl/\n/usr/share/doc/curl/README.Debian\n/usr/share/doc/curl/changelog.Debian.gz",
			},
			packages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantPackages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantErr: cmpopts.AnyError,
		},
		{
			desc: "contains_binary",
			infoContents: map[string]string{
				"curl.list": "/usr/\n/usr/bin/\n/usr/bin/curl\n/usr/share/\n/usr/share/doc/\n/usr/share/doc/curl/\n/usr/share/doc/curl/README.Debian\n/usr/share/doc/curl/changelog.Debian.gz",
			},
			packages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantPackages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
		},
		{
			desc: "does_not_contain_binary",
			infoContents: map[string]string{
				"curl.list": "/usr/\n/usr/share/\n/usr/share/doc/\n/usr/share/doc/curl/\n/usr/share/doc/curl/README.Debian\n/usr/share/doc/curl/changelog.Debian.gz",
			},
			packages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{}},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "curl",
					Metadata: dpkgmetadata.Metadata{},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{
						{
							Plugin:          dpkg.Name,
							Justification:   vex.ComponentNotPresent,
							MatchesAllVulns: true,
						},
					}},
			},
		},
		{
			desc: "arch_specific_path",
			infoContents: map[string]string{
				"curl:arm64.list": "/usr/\n/usr/share/\n/usr/share/doc/\n/usr/share/doc/curl/\n/usr/share/doc/curl/README.Debian\n/usr/share/doc/curl/changelog.Debian.gz",
			},
			packages: []*extractor.Package{
				{Name: "curl", Metadata: dpkgmetadata.Metadata{Architecture: "arm64"}},
			},
			wantPackages: []*extractor.Package{
				{
					Name:     "curl",
					Metadata: dpkgmetadata.Metadata{Architecture: "arm64"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{
						{
							Plugin:          dpkg.Name,
							Justification:   vex.ComponentNotPresent,
							MatchesAllVulns: true,
						},
					}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			root := ""
			if tt.infoContents != nil {
				root = setupDPKGInfo(t, tt.infoContents)
			}
			if tt.ctx == nil {
				tt.ctx = context.Background()
			}
			input := &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(root),
			}
			// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := dpkg.New().Annotate(tt.ctx, input, inv)
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
