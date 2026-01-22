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
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/noexecutable/dpkg"
	"github.com/google/osv-scalibr/common/linux/dpkg/testing/dpkgutil"
	"github.com/google/osv-scalibr/extractor"
	dpkgmetadata "github.com/google/osv-scalibr/extractor/filesystem/os/dpkg/metadata"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"google.golang.org/protobuf/proto"
)

func TestAnnotate(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	cancelledContext, cancel := context.WithCancel(t.Context())
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
				root = dpkgutil.SetupDPKGInfo(t, tt.infoContents, true)
			}
			if tt.ctx == nil {
				tt.ctx = t.Context()
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
