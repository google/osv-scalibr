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

package podman_test

import (
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/testing/extracttest"
)

func TestExtractor_FileRequired(t *testing.T) {
	tests := []struct {
		inputPath string
		want      bool
	}{
		{
			inputPath: "", want: false,
		},
		{
			inputPath: "/home/user/.local/share/containers/storage/db.sql", want: true,
		},
		{
			inputPath: "/home/user/.local/share/containers/storage/libpod/bolt_state.db", want: true,
		},
		{
			inputPath: "/home/user/.local/something.db", want: false,
		},
		{
			inputPath: "/home/user/.local/db.sql", want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.inputPath, func(t *testing.T) {
			e := podman.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.inputPath, nil))
			if got != tt.want {
				t.Errorf("FileRequired(%s) got = %v, want %v", tt.inputPath, got, tt.want)
			}
		})
	}
}

func must[T any](t T, err error) T {
	if err != nil {
		panic(err)
	}
	return t
}

func TestExtractor_Extract(t *testing.T) {
	// extracttest.TestTableEntry + podman config
	type testTableEntry struct {
		Name          string
		InputConfig   extracttest.ScanInputMockConfig
		WantInventory []*extractor.Inventory
		WantErr       error
		Config        podman.Config
	}

	tests := []testTableEntry{
		{
			// The SQLite driver doesn't fail when opening an improperly formatted file,
			// so the error appears during the container listing phase.
			Name: "invalid sqlite db",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/notdb.sql",
			},
			WantErr: extracttest.ContainsErrStr{Str: "Error listing containers in file"},
		},
		{
			Name: "invalid boltstatedb",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/not_bolt_state.db",
			},
			WantErr: extracttest.ContainsErrStr{Str: "Error opening file"},
		},
		{
			Name: "valid using sqlite3 - all",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/db.sql",
			},
			Config: podman.Config{All: true},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "docker.io/hello-world",
					Version: "f1f77a0f96b7251d7ef5472705624e2d76db64855b5b121e1cbefe9dc52d0f86",
					Metadata: &podman.Metadata{
						Status: "exited",
						Exited: true,
					},
				},
				{
					Name:    "postgres",
					Version: "e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{5432: {"tcp"}},
						PID:          37461,
						Status:       "running",
					},
				},
				{
					Name:    "redis",
					Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{6379: {"tcp"}},
						PID:          37379,
						Status:       "running",
					},
				},
			},
		},
		{
			Name: "valid using sqlite3 - running",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/db.sql",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "postgres",
					Version: "e92968df83750a723114bf998e3e323dda53e4c5c3ea42b22dd6ad6e3df80ca5",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{5432: {"tcp"}},
						PID:          37461,
						Status:       "running",
					},
				},
				{
					Name:    "redis",
					Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{6379: {"tcp"}},
						PID:          37379,
						Status:       "running",
					},
				},
			},
		},
		{
			Name: "valid using bolt - all",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bolt_state.db",
			},
			Config: podman.Config{All: true},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "docker.io/hello-world",
					Version: "f1f77a0f96b7251d7ef5472705624e2d76db64855b5b121e1cbefe9dc52d0f86",
					Metadata: &podman.Metadata{
						Status: "exited",
						Exited: true,
					},
				},
				{
					Name:    "docker.io/redis",
					Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{6379: {"tcp"}},
						PID:          4232,
						Status:       "running",
					},
				},
			},
		},
		{
			Name: "valid using bolt",
			InputConfig: extracttest.ScanInputMockConfig{
				Path: "testdata/bolt_state.db",
			},
			WantInventory: []*extractor.Inventory{
				{
					Name:    "docker.io/redis",
					Version: "a8036f14f15ead9517115576fb4462894a000620c2be556410f6c24afb8a482b",
					Metadata: &podman.Metadata{
						ExposedPorts: map[uint16][]string{6379: {"tcp"}},
						PID:          4232,
						Status:       "running",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			extr := podman.New(tt.Config)

			scanInput := extracttest.GenerateScanInputMock(t, tt.InputConfig)
			defer extracttest.CloseTestScanInput(t, scanInput)

			got, err := extr.Extract(context.Background(), &scanInput)
			if diff := cmp.Diff(tt.WantErr, err, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("%s.Extract(%q) error diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
				return
			}

			opts := []cmp.Option{cmpopts.SortSlices(extracttest.InventoryCmpLess), cmpopts.IgnoreTypes(time.Time{})}
			if diff := cmp.Diff(tt.WantInventory, got, opts...); diff != "" {
				t.Errorf("%s.Extract(%q) diff (-want +got):\n%s", extr.Name(), tt.InputConfig.Path, diff)
			}
		})
	}
}
