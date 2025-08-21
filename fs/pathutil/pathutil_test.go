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

package pathutil

import (
	"runtime"
	"testing"
)

func TestNormalizePath(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		isVirtual bool
		expected  string
	}{
		{
			name:      "virtual_path_with_backslashes",
			path:      "app\\src\\main.go",
			isVirtual: true,
			expected:  "app/src/main.go",
		},
		{
			name:      "virtual_path_already_normalized",
			path:      "app/src/main.go",
			isVirtual: true,
			expected:  "app/src/main.go",
		},
		{
			name:      "real_path_unix",
			path:      "app/src/main.go",
			isVirtual: false,
			expected:  "app/src/main.go",
		},
		{
			name:      "empty_path",
			path:      "",
			isVirtual: true,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NormalizePath(tt.path, tt.isVirtual)
			if got != tt.expected {
				t.Errorf("NormalizePath(%q, %v) = %q, want %q", tt.path, tt.isVirtual, got, tt.expected)
			}
		})
	}
}

func TestToVirtualPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "windows_path",
			path:     "C:\\Users\\test\\file.txt",
			expected: "C:/Users/test/file.txt",
		},
		{
			name:     "unix_path",
			path:     "/home/test/file.txt",
			expected: "/home/test/file.txt",
		},
		{
			name:     "mixed_separators",
			path:     "app\\src/main.go",
			expected: "app/src/main.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ToVirtualPath(tt.path)
			if got != tt.expected {
				t.Errorf("ToVirtualPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestJoinVirtual(t *testing.T) {
	tests := []struct {
		name     string
		elements []string
		expected string
	}{
		{
			name:     "simple_join",
			elements: []string{"app", "src", "main.go"},
			expected: "app/src/main.go",
		},
		{
			name:     "with_backslashes",
			elements: []string{"app\\src", "test", "file.txt"},
			expected: "app/src/test/file.txt",
		},
		{
			name:     "empty_elements",
			elements: []string{},
			expected: "",
		},
		{
			name:     "single_element",
			elements: []string{"file.txt"},
			expected: "file.txt",
		},
		{
			name:     "with_double_slashes",
			elements: []string{"app//src", "test"},
			expected: "app/src/test",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := JoinVirtual(tt.elements...)
			if got != tt.expected {
				t.Errorf("JoinVirtual(%v) = %q, want %q", tt.elements, got, tt.expected)
			}
		})
	}
}

func TestStripDriveLetter(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "windows_drive_with_backslash",
			path:     "C:\\Users\\test",
			expected: "Users\\test",
		},
		{
			name:     "windows_drive_with_slash",
			path:     "C:/Users/test",
			expected: "Users/test",
		},
		{
			name:     "unix_absolute_path",
			path:     "/home/test",
			expected: "/home/test", // Should be unchanged on non-Windows
		},
		{
			name:     "relative_path",
			path:     "app/src/main.go",
			expected: "app/src/main.go",
		},
		{
			name:     "drive_only",
			path:     "C:",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := StripDriveLetter(tt.path)
			
			// On non-Windows systems, paths should be unchanged unless they have drive letters
			if runtime.GOOS != "windows" && !containsDriveLetter(tt.path) {
				if got != tt.path {
					t.Errorf("StripDriveLetter(%q) = %q, want %q (unchanged on non-Windows)", tt.path, got, tt.path)
				}
				return
			}
			
			if got != tt.expected {
				t.Errorf("StripDriveLetter(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestSplitPath(t *testing.T) {
	tests := []struct {
		name         string
		path         string
		expectedDir  string
		expectedFile string
	}{
		{
			name:         "simple_path",
			path:         "app/src/main.go",
			expectedDir:  "app/src",
			expectedFile: "main.go",
		},
		{
			name:         "windows_path",
			path:         "app\\src\\main.go",
			expectedDir:  "app/src",
			expectedFile: "main.go",
		},
		{
			name:         "file_only",
			path:         "main.go",
			expectedDir:  "",
			expectedFile: "main.go",
		},
		{
			name:         "root_file",
			path:         "/main.go",
			expectedDir:  "",
			expectedFile: "main.go",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotDir, gotFile := SplitPath(tt.path)
			if gotDir != tt.expectedDir || gotFile != tt.expectedFile {
				t.Errorf("SplitPath(%q) = (%q, %q), want (%q, %q)", 
					tt.path, gotDir, gotFile, tt.expectedDir, tt.expectedFile)
			}
		})
	}
}

func TestContainsPath(t *testing.T) {
	tests := []struct {
		name     string
		parent   string
		child    string
		expected bool
	}{
		{
			name:     "child_in_parent",
			parent:   "/app",
			child:    "/app/src/main.go",
			expected: true,
		},
		{
			name:     "child_equals_parent",
			parent:   "/app",
			child:    "/app",
			expected: true,
		},
		{
			name:     "child_outside_parent",
			parent:   "/app",
			child:    "/other/file.txt",
			expected: false,
		},
		{
			name:     "path_traversal_attempt",
			parent:   "/app",
			child:    "/app/../etc/passwd",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ContainsPath(tt.parent, tt.child)
			if got != tt.expected {
				t.Errorf("ContainsPath(%q, %q) = %v, want %v", tt.parent, tt.child, got, tt.expected)
			}
		})
	}
}

func TestValidatePathSafety(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "safe_relative_path",
			path:     "app/src/main.go",
			expected: true,
		},
		{
			name:     "path_traversal",
			path:     "../../../etc/passwd",
			expected: false,
		},
		{
			name:     "absolute_path",
			path:     "/etc/passwd",
			expected: false,
		},
		{
			name:     "current_directory",
			path:     ".",
			expected: true,
		},
		{
			name:     "hidden_traversal",
			path:     "app/../../../etc/passwd",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ValidatePathSafety(tt.path)
			if got != tt.expected {
				t.Errorf("ValidatePathSafety(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestEnsureTrailingSlash(t *testing.T) {
	tests := []struct {
		name      string
		path      string
		isVirtual bool
		expected  string
	}{
		{
			name:      "virtual_without_slash",
			path:      "app/src",
			isVirtual: true,
			expected:  "app/src/",
		},
		{
			name:      "virtual_with_slash",
			path:      "app/src/",
			isVirtual: true,
			expected:  "app/src/",
		},
		{
			name:      "empty_path",
			path:      "",
			isVirtual: true,
			expected:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EnsureTrailingSlash(tt.path, tt.isVirtual)
			if got != tt.expected {
				t.Errorf("EnsureTrailingSlash(%q, %v) = %q, want %q", tt.path, tt.isVirtual, got, tt.expected)
			}
		})
	}
}

func TestRemoveTrailingSlash(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "with_trailing_slash",
			path:     "app/src/",
			expected: "app/src",
		},
		{
			name:     "with_trailing_backslash",
			path:     "app\\src\\",
			expected: "app\\src",
		},
		{
			name:     "without_trailing_slash",
			path:     "app/src",
			expected: "app/src",
		},
		{
			name:     "root_slash",
			path:     "/",
			expected: "/",
		},
		{
			name:     "empty_path",
			path:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RemoveTrailingSlash(tt.path)
			if got != tt.expected {
				t.Errorf("RemoveTrailingSlash(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

// Helper function to check if a path contains a Windows drive letter
func containsDriveLetter(path string) bool {
	return len(path) >= 2 && path[1] == ':'
}