//go:build !linux

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

package dockersocket

import (
	"context"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/packageindex"
	"github.com/google/osv-scalibr/plugin"
)

func TestScanFS_Dummy(t *testing.T) {
	// Test dummy implementation - should always return empty finding
	fsys := fstest.MapFS{}

	d := &Detector{}
	finding, err := d.ScanFS(context.Background(), fsys, &packageindex.PackageIndex{})

	if err != nil {
		t.Errorf("ScanFS() returned error: %v", err)
	}

	if len(finding.GenericFindings) != 0 {
		t.Errorf("ScanFS() dummy implementation should return empty finding, got: %v", finding)
	}
}

func TestDetectorInterface_Dummy(t *testing.T) {
	d := New()

	if d.Name() != Name {
		t.Errorf("Name() = %q, want %q", d.Name(), Name)
	}

	if d.Version() != 0 {
		t.Errorf("Version() = %d, want 0", d.Version())
	}

	if len(d.RequiredExtractors()) != 0 {
		t.Errorf("RequiredExtractors() = %v, want empty slice", d.RequiredExtractors())
	}

	reqs := d.Requirements()
	if reqs.OS != plugin.OSLinux {
		t.Errorf("Requirements().OS = %q, want %q", reqs.OS, plugin.OSLinux)
	}
}
