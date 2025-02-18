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

package containerd_test

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/internal/units"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
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
			name:           "containerd metadb linux",
			path:           "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db",
			onGoos:         "linux",
			wantIsRequired: true,
		},
		{
			name: "containerd metadb windows",
			path: "ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db",
			// TODO(b/350963790): Enable this test case once the extractor is supported on Windows.
			onGoos:         "ignore",
			wantIsRequired: true,
		},
		{
			name:           "random metadb linux",
			path:           "var/lib/containerd/random/meta.db",
			onGoos:         "linux",
			wantIsRequired: false,
		},
		{
			name:           "container metadb freebsd",
			path:           "var/lib/containerd/random/meta.db",
			onGoos:         "freebsd",
			wantIsRequired: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.onGoos != "" && tt.onGoos != runtime.GOOS {
				t.Skipf("Skipping test on %s", runtime.GOOS)
			}

			isRequired := e.FileRequired(simplefileapi.New(tt.path, nil))
			if isRequired != tt.wantIsRequired {
				t.Fatalf("FileRequired(%s): got %v, want %v", tt.path, isRequired, tt.wantIsRequired)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name              string
		path              string
		snapshotterdbpath string // path to metadata.db file, will be used for Linux test cases.
		statusFilePath    string // path to status file, will be used for Linux test cases.
		shimPIDFilePath   string // path to shim.pid, will be used for Windows test cases.
		namespace         string
		containerdID      string
		cfg               containerd.Config
		onGoos            string
		wantInventory     []*extractor.Inventory
		wantErr           error
	}{
		{
			name:              "metadb valid linux",
			path:              "testdata/meta_linux_test_single.db",
			snapshotterdbpath: "testdata/metadata_linux_test.db",
			statusFilePath:    "testdata/status",
			namespace:         "default",
			containerdID:      "a24fc689ea380bf71604d7ade8f5655b8de66bbbd1befa6c326797f01ce569ce",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			onGoos: "linux",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/eks-pod-identity-agent:0.1.15",
					Version: "sha256:832ad48c9872fdcae32f2ea369d9874fa34f2ea369d9874fa34f271b4dbc58ce04393c757befa462",
					Metadata: &containerd.Metadata{
						Namespace:   "k8s.io",
						ImageName:   "602401143452.dkr.ecr.us-west-2.amazonaws.com/eks/eks-pod-identity-agent:0.1.15",
						ImageDigest: "sha256:832ad48c9872fdcae32f2ea369d9874fa34f2ea369d9874fa34f271b4dbc58ce04393c757befa462",
						Runtime:     "io.containerd.runc.v2",
						ID:          "b47fb93b51d091e16ae145b8b1438e5c011fd68cd65305fcd42fd83a13da7a8c",
						PID:         3530,
						Snapshotter: "overlayfs",
						SnapshotKey: "b47fb93b51d091e16ae145b8b1438e5c011fd68cd65305fcd42fd83a13da7a8c",
						LowerDir:    "/tmp/TestExtractmetadb_valid_linux1567346986/001/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/14/fs:/tmp/TestExtractmetadb_valid_linux1567346986/001/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/13/fs:/tmp/TestExtractmetadb_valid_linux1567346986/001/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/7/fs",
						UpperDir:    "/tmp/TestExtractmetadb_valid_linux1567346986/001/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/16/fs",
						WorkDir:     "/tmp/TestExtractmetadb_valid_linux1567346986/001/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/16/work",
					},
					Locations: []string{"var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db"},
				},
			},
		},
		{
			name:              "metadb invalid",
			path:              "testdata/invalid_meta.db",
			statusFilePath:    "testdata/status",
			snapshotterdbpath: "testdata/metadata_linux_test.db",
			namespace:         "default",
			containerdID:      "test_pod",
			onGoos:            "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name:              "metadb too large",
			path:              "testdata/meta_linux_too_big.db",
			statusFilePath:    "testdata/status",
			snapshotterdbpath: "testdata/metadata_linux_test.db",
			namespace:         "default",
			containerdID:      "test_pod",
			onGoos:            "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 1 * units.KiB,
			},
			wantInventory: []*extractor.Inventory{},
			wantErr:       cmpopts.AnyError,
		},
		{
			name:              "invalid status file",
			path:              "testdata/meta_linux_test_single.db",
			statusFilePath:    "testdata/invalid_status",
			snapshotterdbpath: "testdata/metadata_linux_test.db",
			namespace:         "default",
			containerdID:      "test_pod",
			onGoos:            "linux",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			wantInventory: []*extractor.Inventory{},
		},
		{
			name:            "metadb valid windows",
			path:            "testdata/meta_windows.db",
			shimPIDFilePath: "testdata/shim.pid",
			namespace:       "default",
			containerdID:    "test_pod",
			cfg: containerd.Config{
				MaxMetaDBFileSize: 500 * units.MiB,
			},
			// TODO(b/350963790): Enable this test case once the extractor is supported on Windows.
			onGoos: "ignore",
			wantInventory: []*extractor.Inventory{
				{
					Name:    "mcr.microsoft.com/windows/nanoserver:ltsc2022",
					Version: "sha256:31c8aa02d47af7d65c11da9c3a279c8407c32afd3fc6bec2e9a544db8e3715b3",
					Metadata: &containerd.Metadata{
						Namespace:   "default",
						ImageName:   "mcr.microsoft.com/windows/nanoserver:ltsc2022",
						ImageDigest: "sha256:31c8aa02d47af7d65c11da9c3a279c8407c32afd3fc6bec2e9a544db8e3715b3",
						Runtime:     "io.containerd.runhcs.v1",
						ID:          "test_pod",
						PID:         5628,
					},
					Locations: []string{"ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db"},
				},
			},
		},
		{
			name:            "invalid shim pid",
			path:            "testdata/meta_windows.db",
			shimPIDFilePath: "testdata/state.json",
			namespace:       "default",
			containerdID:    "test_pod",
			// TODO(b/350963790): Enable this test case once the extractor is supported on Windows.
			onGoos: "ignore",
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

			var input *filesystem.ScanInput
			d := "/tmp/TestExtractmetadb_valid_linux1567346986/001"
			if tt.onGoos == "linux" {
				createFileFromTestData(t, d, "var/lib/containerd/io.containerd.metadata.v1.bolt", "meta.db", tt.path)
				createFileFromTestData(t, d, "var/lib/containerd/io.containerd.snapshotter.v1.overlayfs", "metadata.db", tt.snapshotterdbpath)
				createFileFromTestData(t, d, "var/lib/containerd/io.containerd.grpc.v1.cri/containers/b47fb93b51d091e16ae145b8b1438e5c011fd68cd65305fcd42fd83a13da7a8c", "status", tt.statusFilePath)
				input = createScanInput(t, d, "var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db")
			}
			if tt.onGoos == "windows" {
				createFileFromTestData(t, d, "ProgramData/containerd/root/io.containerd.metadata.v1.bolt", "meta.db", tt.path)
				createFileFromTestData(t, d, filepath.Join("ProgramData/containerd/state/io.containerd.runtime.v2.task/", tt.namespace, tt.containerdID), "shim.pid", tt.shimPIDFilePath)
				input = createScanInput(t, d, "ProgramData/containerd/root/io.containerd.metadata.v1.bolt/meta.db")
			}

			e := containerd.New(defaultConfigWith(tt.cfg))
			got, err := e.Extract(t.Context(), input)
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

func createFileFromTestData(t *testing.T, root string, subPath string, fileName string, testDataFilePath string) {
	t.Helper()
	os.MkdirAll(filepath.Join(root, subPath), 0755)
	testData, err := os.ReadFile(testDataFilePath)
	if err != nil {
		t.Fatalf("read from %s: %v\n", testDataFilePath, err)
	}
	err = os.WriteFile(filepath.Join(root, subPath, fileName), testData, 0644)
	if err != nil {
		t.Fatalf("write to %s: %v\n", filepath.Join(root, subPath, fileName), err)
	}
}

func createScanInput(t *testing.T, root string, path string) *filesystem.ScanInput {
	t.Helper()

	finalPath := filepath.Join(root, path)
	reader, err := os.Open(finalPath)
	defer func() {
		if err = reader.Close(); err != nil {
			t.Errorf("Close(): %v", err)
		}
	}()
	if err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	input := &filesystem.ScanInput{Path: path, Reader: reader, Root: root, Info: info}
	return input
}

// defaultConfigWith combines any non-zero fields of cfg with packagejson.DefaultConfig().
func defaultConfigWith(cfg containerd.Config) containerd.Config {
	newCfg := containerd.DefaultConfig()

	if cfg.MaxMetaDBFileSize > 0 {
		newCfg.MaxMetaDBFileSize = cfg.MaxMetaDBFileSize
	}

	return newCfg
}
