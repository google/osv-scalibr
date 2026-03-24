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
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		fileSize int64
		want     bool
	}{
		{
			name:     "exe_file_required",
			path:     "C:/Program Files/WinRAR/WinRAR.exe",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "dll_file_required",
			path:     "C:/Program Files/WinRAR/RarExt.dll",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "uppercase_exe_required",
			path:     "C:/Program Files/App/test.EXE",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "uppercase_dll_required",
			path:     "C:/Program Files/App/test.DLL",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "txt_file_not_required",
			path:     "C:/Users/test/readme.txt",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "json_file_not_required",
			path:     "C:/Users/test/config.json",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "no_extension_not_required",
			path:     "C:/Users/test/somefile",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "system32_exe_skipped",
			path:     "C:/Windows/System32/notepad.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "winsxs_dll_skipped",
			path:     "C:/Windows/WinSxS/some_assembly/test.dll",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "servicing_exe_skipped",
			path:     "C:/Windows/Servicing/packages/test.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "software_distribution_exe_skipped",
			path:     "C:/Windows/SoftwareDistribution/Download/test.exe",
			fileSize: 1000,
			want:     false,
		},
		{
			name:     "file_larger_than_max_skipped",
			path:     "C:/Program Files/Large/huge.exe",
			fileSize: 350 * 1024 * 1024, // 350 MB
			want:     false,
		},
		{
			name:     "file_exactly_max_size_required",
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

func TestFileRequired_skip_system_dirs_disabled(t *testing.T) {
	config := peversion.Config{
		SkipSystemDirs:   false,
		MaxFileSizeBytes: 300 * 1024 * 1024,
	}
	extractor := peversion.NewWithConfig(config)

	tests := []struct {
		name     string
		path     string
		fileSize int64
		want     bool
	}{
		{
			name:     "system32_exe_required_when_skip_disabled",
			path:     "C:/Windows/System32/notepad.exe",
			fileSize: 1000,
			want:     true,
		},
		{
			name:     "winsxs_dll_required_when_skip_disabled",
			path:     "C:/Windows/WinSxS/some_assembly/test.dll",
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

func TestFileRequired_custom_max_file_size(t *testing.T) {
	config := peversion.Config{
		SkipSystemDirs:   true,
		MaxFileSizeBytes: 10 * 1024 * 1024, // 10 MB
	}
	extractor := peversion.NewWithConfig(config)

	tests := []struct {
		name     string
		path     string
		fileSize int64
		want     bool
	}{
		{
			name:     "file_under_custom_limit_required",
			path:     "C:/Program Files/App/small.exe",
			fileSize: 5 * 1024 * 1024, // 5 MB
			want:     true,
		},
		{
			name:     "file_over_custom_limit_skipped",
			path:     "C:/Program Files/App/big.exe",
			fileSize: 15 * 1024 * 1024, // 15 MB
			want:     false,
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
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "dots_unchanged", input: "1.0.0", want: "1.0.0"},
		{name: "underscores_to_dots", input: "1_0_0", want: "1.0.0"},
		{name: "hyphens_to_dots", input: "1-0-0", want: "1.0.0"},
		{name: "whitespace_trimmed", input: "  1.0.0  ", want: "1.0.0"},
		{name: "mixed_separators", input: "1_0-0", want: "1.0.0"},
		{name: "empty_string", input: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peversion.NormalizeVersion(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestShouldSkipSystemDir(t *testing.T) {
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "system32_skipped", path: "C:/Windows/System32/file.exe", want: true},
		{name: "winsxs_skipped", path: "C:/Windows/WinSxS/file.dll", want: true},
		{name: "servicing_skipped", path: "C:/Windows/Servicing/file.exe", want: true},
		{name: "software_distribution_skipped", path: "C:/Windows/SoftwareDistribution/file.exe", want: true},
		{name: "program_files_not_skipped", path: "C:/Program Files/App/file.exe", want: false},
		{name: "users_dir_not_skipped", path: "C:/Users/test/file.dll", want: false},
		{name: "backslash_paths_skipped", path: "C:\\Windows\\System32\\notepad.exe", want: true},
		{name: "case_insensitive", path: "C:/WINDOWS/SYSTEM32/file.exe", want: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := peversion.ShouldSkipSystemDir(tt.path)
			if got != tt.want {
				t.Errorf("ShouldSkipSystemDir(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}
