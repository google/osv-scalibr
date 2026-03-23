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

package apk_test

import (
	"context"
	"os"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate/apk"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/testing/fakefs"
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
		fakeFS   string
		packages []*extractor.Package
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc:   "empty_db",
			fakeFS: "testdata/empty",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
		},
		{
			desc:   "one_found_in_db-one_not(empty_cache)",
			fakeFS: "testdata/nocache",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
				{
					Name:      "not-in-db",
					Locations: []string{"path/not/in/db"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          apk.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:      "not-in-db",
					Locations: []string{"path/not/in/db"},
				},
			},
		},
		{
			desc:   "both_found-one_from_main_one_not",
			fakeFS: "testdata/cache",
			packages: []*extractor.Package{
				{
					Name:      "libcurl",
					Version:   "8.17.0-r1",
					Locations: []string{"usr/lib/libcurl.so.4.8.0"},
				},
				{
					Name:      "orb",
					Version:   "1.4.10",
					Locations: []string{"usr/bin/orb-update"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libcurl",
					Version:   "8.17.0-r1",
					Locations: []string{"usr/lib/libcurl.so.4.8.0"},
					ExploitabilitySignals: []*vex.PackageExploitabilitySignal{&vex.PackageExploitabilitySignal{
						Plugin:          apk.Name,
						Justification:   vex.ComponentNotPresent,
						MatchesAllVulns: true,
					}},
				},
				{
					Name:      "orb",
					Version:   "1.4.10",
					Locations: []string{"usr/bin/orb-update"},
				},
			},
		},
		{
			desc:   "ctx_cancelled",
			ctx:    cancelledContext,
			fakeFS: "testdata/nocache",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Version:   "14.2.0-r6",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
					// No annotations
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
			content, err := os.ReadFile(tt.fakeFS)
			if err != nil {
				t.Fatal(err)
			}
			fakeFS, err := fakefs.PrepareFS(string(content), fakefs.TarGzModifier)
			if err != nil {
				t.Fatal(err)
			}
			input := &annotator.ScanInput{
				ScanRoot: &scalibrfs.ScanRoot{FS: fakeFS},
			}

			// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			anno, err := apk.New(&cpb.PluginConfig{})
			if err != nil {
				t.Fatal(err)
			}

			err = anno.Annotate(tt.ctx, input, inv)
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
