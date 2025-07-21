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

package apk_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-cpy/cpy"
	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/osduplicate/apk"
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
		apkDB    string
		packages []*extractor.Package
		//nolint:containedctx
		ctx          context.Context
		wantErr      error
		wantPackages []*extractor.Package
	}{
		{
			desc:  "empty_db",
			apkDB: "testdata/empty",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
		},
		{
			desc:  "some_pkgs_found_in_db",
			apkDB: "testdata/some",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
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
			desc:  "ctx_cancelled",
			ctx:   cancelledContext,
			apkDB: "testdata/some",
			packages: []*extractor.Package{
				{
					Name:      "libstdc++",
					Locations: []string{"usr/lib/libstdc++.so.6.0.33"},
				},
			},
			wantPackages: []*extractor.Package{
				{
					Name:      "libstdc++",
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

			tmpPath := setupApkDB(t, tt.apkDB)
			input := &annotator.ScanInput{
				ScanRoot: scalibrfs.RealFSScanRoot(tmpPath),
			}

			// Deep copy the packages to avoid modifying the original inventory that is used in other tests.
			packages := copier.Copy(tt.packages).([]*extractor.Package)
			inv := &inventory.Inventory{Packages: packages}

			err := apk.New().Annotate(tt.ctx, input, inv)
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

// Sets up the apk db
func setupApkDB(t *testing.T, file string) string {
	t.Helper()
	dir := t.TempDir()
	dbFolder := filepath.Join(dir, "lib/apk/db/")
	if err := os.MkdirAll(dbFolder, 0777); err != nil {
		t.Fatalf("error creating directory %q: %v", dbFolder, err)
	}

	content, err := os.ReadFile(file)
	if err != nil {
		t.Fatalf("Error reading content file %q: %v", content, err)
	}

	dbFile := filepath.Join(dbFolder, "installed")
	if err := os.WriteFile(dbFile, content, 0644); err != nil {
		t.Fatalf("Error creating file %q: %v", dbFile, err)
	}

	return dir
}
