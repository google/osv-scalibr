// Copyright 2024 Google LLC
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

package containerd_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
)

func TestFileRequired(t *testing.T) {
	var e filesystem.Extractor = containerd.Extractor{}

	tests := []struct {
		name           string
		path           string
		onGoos         string
		wantIsRequired bool
	}{
		{
			name:           "containerd metadb",
			path:           "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
			onGoos:         "linux",
			wantIsRequired: true,
		},
		// TODO(b/349138656): Change this test when containerd is supported for Windows.
		{
			name:           "containerd metadb windows",
			path:           "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
			onGoos:         "windows",
			wantIsRequired: false,
		},
		{
			name:           "random metadb",
			path:           "var/lib/containerd/random/meta.db",
			onGoos:         "linux",
			wantIsRequired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.onGoos != "" && tt.onGoos != runtime.GOOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			isRequired := e.FileRequired(tt.path, nil)
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name          string
		path          string
		stateFilePath string
		namespace     string
		containerdID  string
		cfg           containerd.Config
		onGoos        string
		wantInventory []*extractor.Inventory
		wantErr       error
	}{
		{
			name:          "metadb valid",
			path:          "testdata/meta.db",
			stateFilePath: "testdata/state.json",
			namespace:     "default",
			containerdID:  "test_pod",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			onGoos: "linux",
			wantInventory: []*extractor.Inventory{
				&extractor.Inventory{
					Name:    "gcr.io/google-samples/hello-app:1.0",
					Version: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
					Metadata: &containerd.Metadata{
						Namespace:   "default",
						ImageName:   "gcr.io/google-samples/hello-app:1.0",
						ImageDigest: "sha256:b1455e1c4fcc5ea1023c9e3b584cd84b64eb920e332feff690a2829696e379e7",
						PID:         8915,
					},
					Locations: []string{"testdata/meta.db"},
				},
			},
		},
		{
			name:          "metadb invalid",
			path:          "testdata/invalid_meta.db",
			stateFilePath: "testdata/state.json",
			namespace:     "default",
			containerdID:  "test_pod",
			onGoos:        "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name:          "metadb too large",
			path:          "testdata/meta.db",
			stateFilePath: "testdata/state.json",
			namespace:     "default",
			containerdID:  "test_pod",
			onGoos:        "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 1 * units.KiB,
			},
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name:          "invalid state json",
			path:          "testdata/meta.db",
			stateFilePath: "testdata/invalid_state.json",
			namespace:     "default",
			containerdID:  "test_pod",
			onGoos:        "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:          "invalid state",
			path:          "testdata/meta.db",
			stateFilePath: "testdata/invalid_json",
			namespace:     "default",
			containerdID:  "test_pod",
			onGoos:        "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			wantInventory: []*extractor.Inventory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.onGoos != "" && tt.onGoos != runtime.GOOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			d := t.TempDir()
			createRuncStateFromTestData(t, d, tt.namespace, tt.containerdID, tt.stateFilePath)
			createContainerdStateFromTestData(t, d, tt.path)
			tt.wantInventory = modifyInventoryLocationsForTest(tt.wantInventory, d)
			r, err := os.Open(filepath.Join(d, "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"))
			defer func() {
				if err = r.Close(); err != nil {
					t.Errorf("Close(): %v", err)
				}
			}()
			if err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(tt.path)
			if err != nil {
				t.Fatal(err)
			}

			input := &filesystem.ScanInput{Path: filepath.Join(d, "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"), Reader: r, ScanRoot: d, Info: info}
			e := containerd.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(context.Background(), input)
			if !cmp.Equal(err, tt.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Extract(%+v) error: got %v, want %v\n", tt.path, err, tt.wantErr)
			}

			ignoreOrder := cmpopts.SortSlices(func(a, b any) bool {
				return fmt.Sprintf("%+v", a) < fmt.Sprintf("%+v", b)
			})
			if diff := cmp.Diff(tt.wantInventory, got, ignoreOrder); diff != "" {
				t.Errorf("Extract(%s) (-want +got):\n%s", tt.path, diff)
			}
		})
	}
}

func modifyInventoryLocationsForTest(inventory []*extractor.Inventory, root string) []*extractor.Inventory {
	for _, i := range inventory {
		i.Locations = []string{filepath.Join(root, "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db")}
	}
	return inventory
}

func createRuncStateFromTestData(t *testing.T, root string, namespace string, id string, testDataFilePath string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "run/containerd/runc/", namespace, id), 0755)
	stateContent, err := os.ReadFile(testDataFilePath)
	if err != nil {
		t.Fatalf("read from %s: %v\n", testDataFilePath, err)
	}
	err = os.WriteFile(filepath.Join(root, "run/containerd/runc/", namespace, id, "state.json"), []byte(stateContent), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, "run/containerd/runc/", namespace, id, "state.json"), err)
	}
}

func createContainerdStateFromTestData(t *testing.T, root string, testDataFilePath string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, "/var/lib/containerd/io.containerd.metadata.v1.bolt"), 0755)
	metaDbContent, err := os.ReadFile(testDataFilePath)
	if err != nil {
		t.Fatalf("read from %s: %v\n", testDataFilePath, err)
	}
	err = os.WriteFile(filepath.Join(root, "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"), []byte(metaDbContent), 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db", err)
	}
}

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg containerd.Config) containerd.Config {
	newCfg := containerd.DefaultConfig()

	if cfg.MaxMetaDBFileSize > 0 {
		newCfg.MaxMetaDBFileSize = cfg.MaxMetaDBFileSize
	}

	return newCfg
}
