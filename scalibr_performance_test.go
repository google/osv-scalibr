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

package scalibr_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

type benchAllFilesExtractor struct{}

func (benchAllFilesExtractor) Name() string                       { return "bench/allfiles" }
func (benchAllFilesExtractor) Version() int                       { return 1 }
func (benchAllFilesExtractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (benchAllFilesExtractor) FileRequired(api filesystem.FileAPI) bool {
	return strings.HasSuffix(api.Path(), ".txt")
}
func (benchAllFilesExtractor) Extract(_ context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if _, err := input.FS.Stat(input.Path); err != nil {
		return inventory.Inventory{}, err
	}
	return inventory.Inventory{}, nil
}

func populateDeepScanTree(tb testing.TB, dir string) {
	tb.Helper()
	payload := []byte("package-metadata-data")
	// 5 * 5 * 5 = 125 leaf directories at depth 4 (files at depth 5: aX/bY/cZ/leaf/fileW.txt),
	// 20 files per leaf dir = 2,500 files total across 281 directories.
	for a := range 5 {
		for b := range 5 {
			for c := range 5 {
				leaf := filepath.Join(
					dir,
					fmt.Sprintf("a%d", a),
					fmt.Sprintf("b%d", b),
					fmt.Sprintf("c%d", c),
					"leaf",
				)
				if err := os.MkdirAll(leaf, 0o755); err != nil {
					tb.Fatal(err)
				}
				for f := range 20 {
					if err := os.WriteFile(filepath.Join(leaf, fmt.Sprintf("file%d.txt", f)), payload, 0o644); err != nil {
						tb.Fatal(err)
					}
				}
			}
		}
	}
}

func TestScan_Traversal(t *testing.T) {
	dir := t.TempDir()
	populateDeepScanTree(t, dir)

	// Each scan visits 281 directories via diriterate.ReadDir (281 Stat + 281 Open = 562 ops)
	// plus 1 initial Stat(".") plus 2,500 files (each opened by RunFS + Stat in Extract = 5,000 ops)
	// = 5,563 FS operations per Scan().
	const opsPerScan = 5563
	cfg := &scalibr.ScanConfig{
		ScanRoots: scalibrfs.RealFSScanRoots(dir),
		Plugins:   []plugin.Plugin{benchAllFilesExtractor{}},
	}
	start := time.Now()
	res := scalibr.New().Scan(t.Context(), cfg)
	elapsed := time.Since(start)
	if res.Status.Status != plugin.ScanStatusSucceeded {
		t.Fatalf("Scan failed: %s", res.Status.FailureReason)
	}
	t.Logf("[GOOS=%s] Scan() deep tree: %v (%d ops, %v/op)", runtime.GOOS, elapsed, opsPerScan, elapsed/opsPerScan)
}

func BenchmarkScan_Traversal(b *testing.B) {
	dir := b.TempDir()
	populateDeepScanTree(b, dir)

	b.ResetTimer()
	for range b.N {
		cfg := &scalibr.ScanConfig{
			ScanRoots: scalibrfs.RealFSScanRoots(dir),
			Plugins:   []plugin.Plugin{benchAllFilesExtractor{}},
		}
		res := scalibr.New().Scan(b.Context(), cfg)
		if res.Status.Status != plugin.ScanStatusSucceeded {
			b.Fatalf("Scan failed: %s", res.Status.FailureReason)
		}
	}
}
