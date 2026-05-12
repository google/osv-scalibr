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

package common

import (
	"os"
	"sync"
	"testing"

	"github.com/google/osv-scalibr/tempdir"
)

func TestEmbeddedDirFSCloseAndCleanup(t *testing.T) {
	pluginRoot, err := tempdir.CreateDir("test_close_plugin")
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}

	partitionRoot, err := tempdir.CreateDir("test_close_partition")
	if err != nil {
		t.Fatalf("CreateDir failed: %v", err)
	}

	// Create a dummy file
	f, err := os.CreateTemp(t.TempDir(), "dummy_raw")
	if err != nil {
		t.Fatalf("CreateTemp failed: %v", err)
	}

	var refCount int32 = 1
	var refMu sync.Mutex

	edfs := &EmbeddedDirFS{
		Root:                partitionRoot,
		PluginRoot:          pluginRoot,
		File:                f,
		NumOfPartitionsLeft: &refCount,
		RefMu:               &refMu,
	}

	if err := edfs.CloseAndCleanup(); err != nil {
		t.Fatalf("CloseAndCleanup() failed: %v", err)
	}

	if refCount != 0 {
		t.Fatalf("Expected refCount 0, got %d", refCount)
	}

	// Verify that PartitionRoot and PluginRoot are closed by trying to use them.
	if _, err := partitionRoot.Stat("."); err == nil {
		t.Fatal("Expected error using closed partitionRoot, got nil")
	}

	if _, err := pluginRoot.Stat("."); err == nil {
		t.Fatal("Expected error using closed pluginRoot, got nil")
	}
}
