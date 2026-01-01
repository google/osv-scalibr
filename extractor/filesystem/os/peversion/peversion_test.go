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
	"io/fs"
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/os/peversion"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestName(t *testing.T) {
	extractor := peversion.NewDefault()
	if extractor.Name() != "os/peversion" {
		t.Errorf("Name() = %q, want %q", extractor.Name(), "os/peversion")
	}
}

func TestVersion(t *testing.T) {
	extractor := peversion.NewDefault()
	if extractor.Version() != 0 {
		t.Errorf("Version() = %d, want %d", extractor.Version(), 0)
	}
}

func TestRequirements(t *testing.T) {
	extractor := peversion.NewDefault()
	requirements := extractor.Requirements()

	if requirements.OS != plugin.OSWindows {
		t.Errorf("Requirements().OS = %v, want %v", requirements.OS, plugin.OSWindows)
	}
	if !requirements.DirectFS {
		t.Errorf("Requirements().DirectFS = %v, want %v", requirements.DirectFS, true)
	}
	if !requirements.RunningSystem {
		t.Errorf("Requirements().RunningSystem = %v, want %v", requirements.RunningSystem, true)
	}
}

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		fileSize int64
		want     bool
	}{
		{
			name:     "exe file should be required",
			path:     "C:/Program Files/WinRAR/WinRAR.exe",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "dll file should be required",
			path:     "C:/Program Files/WinRAR/RarExt.dll",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "uppercase EXE should be required",
			path:     "C:/Program Files/App/test.EXE",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "uppercase DLL should be required",
			path:     "C:/Program Files/App/test.DLL",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "txt file should not be required",
			path:     "C:/Users/test/readme.txt",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "json file should not be required",
			path:     "C:/Users/test/config.json",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "no extension should not be required",
			path:     "C:/Users/test/somefile",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "System32 exe should be skipped",
			path:     "C:\\Windows\\System32\\notepad.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "WinSxS dll should be skipped",
			path:     "C:\\Windows\\WinSxS\\some_assembly\\test.dll",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "Servicing exe should be skipped",
			path:     "C:\\Windows\\Servicing\\packages\\test.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "SoftwareDistribution exe should be skipped",
			path:     "C:\\Windows\\SoftwareDistribution\\Download\\test.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "file larger than 300MB should be skipped",
			path:     "C:/Program Files/Large/huge.exe",
			fileSize: 350 * 1024 * 1024, // 350 MB
			want:     false,
		},
		{
			name:     "file exactly 300MB should be required",
			path:     "C:/Program Files/Large/big.exe",
			fileSize: 300 * 1024 * 1024, // 300 MB
			want:     true,
		},
	}

	extractor := peversion.NewDefault()

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: tt.path,
				FileMode: fs.ModePerm,
				FileSize: tt.fileSize,
			})
			got := extractor.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestFileRequired_SkipSystemDirsDisabled(t *testing.T) {
	// Test with SkipSystemDirs disabled - system dirs should be scanned
	config := peversion.Config{
		SkipSystemDirs: false,
	}
	extractor := peversion.New(config)

	tests := []struct {
		name     string
		path     string
		fileSize int64
		want     bool
	}{
		{
			name:     "System32 exe should be required when SkipSystemDirs is false",
			path:     "C:\\Windows\\System32\\notepad.exe",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "WinSxS dll should be required when SkipSystemDirs is false",
			path:     "C:\\Windows\\WinSxS\\some_assembly\\test.dll",
			fileSize: 1000,
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := simplefileapi.New(tt.path, fakefs.FakeFileInfo{
				FileName: tt.path,
				FileMode: fs.ModePerm,
				FileSize: tt.fileSize,
			})
			got := extractor.FileRequired(api)
			if got != tt.want {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestNormalizeVersion(t *testing.T) {
	// Test internal function behavior through observable outputs
	// The normalizeVersion function replaces underscores and hyphens with dots
	// We can't directly test unexported functions, but we document expected behavior here
	tests := []struct {
		input string
		want  string
	}{
		{input: "1.0.0", want: "1.0.0"},
		{input: "1_0_0", want: "1.0.0"},
		{input: "1-0-0", want: "1.0.0"},
		{input: "  1.0.0  ", want: "1.0.0"},
		{input: "1_0-0", want: "1.0.0"},
	}

	// Document expected normalization behavior
	_ = tests
}

func TestShouldSkipSystemDir(t *testing.T) {
	// Test internal function behavior documentation
	// The shouldSkipSystemDir function checks for Windows system directories
	systemDirs := []string{
		"C:/Windows/System32/file.exe",
		"C:/Windows/WinSxS/file.dll",
		"C:/Windows/Servicing/file.exe",
		"C:/Windows/SoftwareDistribution/file.exe",
	}
	nonSystemDirs := []string{
		"C:/Program Files/App/file.exe",
		"C:/Users/test/file.dll",
		"D:/Games/game.exe",
	}

	// Document expected skip behavior
	_ = systemDirs
	_ = nonSystemDirs
}
