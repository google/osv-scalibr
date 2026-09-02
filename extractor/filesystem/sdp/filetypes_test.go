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

package sdp

import (
	"testing"

	"github.com/google/osv-scalibr/inventory"
)

func TestGetExtension(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "valid text extension",
			path:     "file.txt",
			expected: "txt",
		},
		{
			name:     "valid image extension",
			path:     "image.png",
			expected: "png",
		},
		{
			name:     "multiple dots",
			path:     "archive.tar.gz",
			expected: "gz",
		},
		{
			name:     "no extension",
			path:     "Makefile",
			expected: "",
		},
		{
			name:     "path ends with dot",
			path:     "file.",
			expected: "",
		},
		{
			name:     "empty path",
			path:     "",
			expected: "",
		},
		{
			name:     "just a dot",
			path:     ".",
			expected: "",
		},
		{
			name:     "hidden file",
			path:     ".bashrc",
			expected: "",
		},
		{
			name:     "hidden file with extension",
			path:     ".hidden.txt",
			expected: "txt",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := getExtension(test.path); got != test.expected {
				t.Errorf("getExtension(%q) = %q, want %q", test.path, got, test.expected)
			}
		})
	}
}

func TestGetFileTypeForPath(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected inventory.FileType
	}{
		{
			name:     "text file",
			path:     "document.txt",
			expected: inventory.TextFileType,
		},
		{
			name:     "image file",
			path:     "photo.png",
			expected: inventory.ImageFileType,
		},
		{
			name:     "JSON file",
			path:     "data.json",
			expected: inventory.JSONFileType,
		},
		{
			name:     "source code file",
			path:     "main.go",
			expected: inventory.SourceCodeFileType,
		},
		{
			name:     "case insensitive extension",
			path:     "REPORT.PDF",
			expected: inventory.PDFFileType,
		},
		{
			name:     "unknown extension",
			path:     "archive.xyz",
			expected: inventory.UnknownFileType,
		},
		{
			name:     "no extension",
			path:     "README",
			expected: inventory.UnknownFileType,
		},
		{
			name:     "path ending with dot",
			path:     "file.",
			expected: inventory.UnknownFileType,
		},
		{
			name:     "image with special suffix",
			path:     "image.jpg:orig",
			expected: inventory.ImageFileType,
		},
		{
			name:     "file name beginning with dot",
			path:     ".file.txt",
			expected: inventory.TextFileType,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := getFileTypeForPath(test.path); got != test.expected {
				t.Errorf("getFileTypeForPath(%q) = %q, want %q", test.path, got, test.expected)
			}
		})
	}
}
