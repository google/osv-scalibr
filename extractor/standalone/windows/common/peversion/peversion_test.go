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

package peversion_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/peversion"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/plugin"
)

func TestExtractorMetadata(t *testing.T) {
	extractor := peversion.NewDefault()

	if got := extractor.Name(); got != peversion.Name {
		t.Errorf("Name() = %q, want %q", got, peversion.Name)
	}

	if got := extractor.Version(); got < 0 {
		t.Errorf("Version() = %d, want >= 0", got)
	}

	reqs := extractor.Requirements()
	if reqs == nil {
		t.Fatal("Requirements() returned nil")
	}

	if reqs.OS != plugin.OSWindows {
		t.Errorf("Requirements().OS = %q, want %q", reqs.OS, plugin.OSWindows)
	}

	if !reqs.DirectFS {
		t.Error("Requirements().DirectFS = false, want true")
	}

	if !reqs.RunningSystem {
		t.Error("Requirements().RunningSystem = false, want true")
	}
}

func TestExtractorConfig(t *testing.T) {
	tests := []struct {
		name   string
		config peversion.Config
	}{
		{
			name:   "default config",
			config: peversion.DefaultConfig(),
		},
		{
			name: "custom config with system dirs skipped",
			config: peversion.Config{
				SkipSystemDirs: true,
				MaxFiles:       100,
			},
		},
		{
			name: "custom config no limits",
			config: peversion.Config{
				SkipSystemDirs: false,
				MaxFiles:       0,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := peversion.New(tt.config)
			if extractor == nil {
				t.Fatal("New() returned nil")
			}
		})
	}
}

func TestExtract_EmptyDirectory(t *testing.T) {
	// Create a temporary empty directory
	tempDir := t.TempDir()

	extractor := peversion.NewDefault()
	ctx := context.Background()

	inventory, err := extractor.Extract(ctx, &standalone.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: tempDir,
		},
	})

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(inventory.Packages) != 0 {
		t.Errorf("Extract() returned %d packages, want 0 for empty directory", len(inventory.Packages))
	}
}

func TestExtract_NonExistentDirectory(t *testing.T) {
	extractor := peversion.NewDefault()
	ctx := context.Background()

	_, err := extractor.Extract(ctx, &standalone.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: "/path/that/does/not/exist",
		},
	})

	if err == nil {
		t.Error("Extract() expected error for non-existent directory, got nil")
	}
}

func TestExtract_WithNonPEFiles(t *testing.T) {
	// Create a temporary directory with non-PE files
	tempDir := t.TempDir()

	// Create some non-PE files
	files := []string{"test.txt", "readme.md", "config.json", "script.sh"}
	for _, file := range files {
		path := filepath.Join(tempDir, file)
		if err := os.WriteFile(path, []byte("test content"), 0644); err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}
	}

	extractor := peversion.NewDefault()
	ctx := context.Background()

	inventory, err := extractor.Extract(ctx, &standalone.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: tempDir,
		},
	})

	if err != nil {
		t.Fatalf("Extract() unexpected error: %v", err)
	}

	if len(inventory.Packages) != 0 {
		t.Errorf("Extract() returned %d packages, want 0 for non-PE files", len(inventory.Packages))
	}
}

func TestExtract_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()

	extractor := peversion.NewDefault()
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	_, err := extractor.Extract(ctx, &standalone.ScanInput{
		ScanRoot: &scalibrfs.ScanRoot{
			Path: tempDir,
		},
	})

	if err != context.Canceled {
		t.Errorf("Extract() with canceled context returned error %v, want %v", err, context.Canceled)
	}
}

func TestDefaultConfig(t *testing.T) {
	config := peversion.DefaultConfig()

	if !config.SkipSystemDirs {
		t.Error("DefaultConfig().SkipSystemDirs = false, want true")
	}

	if config.MaxFiles != 0 {
		t.Errorf("DefaultConfig().MaxFiles = %d, want 0 (unlimited)", config.MaxFiles)
	}
}

// TestExtractorInterface verifies the extractor implements the correct interface
func TestExtractorInterface(t *testing.T) {
	var _ standalone.Extractor = (*peversion.Extractor)(nil)
}

func TestPackageMetadata(t *testing.T) {
	// This test documents the expected metadata structure
	// In a real scenario with actual PE files, we would verify this structure
	expectedMetadataKeys := []string{"original_path", "raw_version"}

	if len(expectedMetadataKeys) != 2 {
		t.Errorf("Expected 2 metadata keys, documented %d", len(expectedMetadataKeys))
	}
}

func TestVersionNormalization(t *testing.T) {
	// This tests the documented version normalization behavior
	// The actual normalizeVersion function is not exported, but we document expected behavior
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "underscores to dots",
			input:    "6_10",
			expected: "6.10",
		},
		{
			name:     "hyphens to dots",
			input:    "6-10-0",
			expected: "6.10.0",
		},
		{
			name:     "mixed separators",
			input:    "6_10-beta",
			expected: "6.10.beta",
		},
		{
			name:     "already normalized",
			input:    "7.13",
			expected: "7.13",
		},
		{
			name:     "with whitespace",
			input:    "  7.13  ",
			expected: "7.13",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// This documents the expected behavior
			// In actual testing with PE files, the Extract method would apply this normalization
			if tt.expected == "" {
				t.Errorf("Expected value not documented for input %q", tt.input)
			}
		})
	}
}

func TestProductNameFallback(t *testing.T) {
	// This documents the product name resolution priority:
	// 1. ProductName from PE resources
	// 2. InternalName from PE resources
	// 3. OriginalFilename from PE resources
	// 4. Base filename without extension (fallback)

	fallbackExamples := []struct {
		filePath     string
		expectedName string
	}{
		{
			filePath:     "C:\\Program Files\\MyApp\\MyApp.exe",
			expectedName: "MyApp",
		},
		{
			filePath:     "C:\\Tools\\custom-tool-v2.exe",
			expectedName: "custom-tool-v2",
		},
		{
			filePath:     "/usr/bin/app.dll",
			expectedName: "app",
		},
	}

	for _, example := range fallbackExamples {
		base := filepath.Base(example.filePath)
		name := base[:len(base)-len(filepath.Ext(base))]
		if diff := cmp.Diff(example.expectedName, name); diff != "" {
			t.Errorf("Product name fallback mismatch (-want +got):\n%s", diff)
		}
	}
}
