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

func TestAnnotate(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	copier := cpy.New(
		cpy.Func(proto.Clone),
		cpy.IgnoreAllUnexported(),
	)

	tests := []struct {
		desc     string
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
					Locations: []string{"path/to/file-not-in-pkgs"},
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
					Locations: []string{"path/to/file-not-in-pkgs"},
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
				tt.ctx = context.Background()
			}
			input := &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(""),
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
