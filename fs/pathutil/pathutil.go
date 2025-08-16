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

// Package pathutil provides cross-platform path utilities for OSV-SCALIBR.
package pathutil

import (
	"path/filepath"
	"runtime"
	"strings"
)

// NormalizePath normalizes a path for cross-platform compatibility.
// It handles Windows drive letters and converts backslashes to forward slashes
// for virtual filesystems while preserving the original path for real filesystems.
func NormalizePath(path string, isVirtual bool) string {
	if path == "" {
		return path
	}
	
	// For virtual filesystems (containers, etc.), always use forward slashes
	if isVirtual {
		return filepath.ToSlash(path)
	}
	
	// For real filesystems, use the OS-appropriate separator
	return filepath.Clean(path)
}

// ToVirtualPath converts a path to virtual filesystem format (forward slashes).
// This is used when storing paths in inventory that should be platform-independent.
func ToVirtualPath(path string) string {
	return filepath.ToSlash(path)
}

// FromVirtualPath converts a virtual path to the current OS format.
// This is used when converting stored paths back to OS-specific format.
func FromVirtualPath(path string) string {
	if runtime.GOOS == "windows" {
		return filepath.FromSlash(path)
	}
	return path
}

// JoinVirtual joins path elements using forward slashes, regardless of OS.
// This ensures consistent path handling in virtual filesystems.
func JoinVirtual(elem ...string) string {
	if len(elem) == 0 {
		return ""
	}
	
	// Convert all elements to use forward slashes
	for i, e := range elem {
		elem[i] = filepath.ToSlash(e)
	}
	
	// Join with forward slashes
	result := strings.Join(elem, "/")
	
	// Clean up any double slashes
	for strings.Contains(result, "//") {
		result = strings.ReplaceAll(result, "//", "/")
	}
	
	return result
}

// IsAbsolute checks if a path is absolute, handling both Unix and Windows formats.
func IsAbsolute(path string) bool {
	return filepath.IsAbs(path)
}

// StripDriveLetter removes the Windows drive letter from a path if present.
// This is useful for creating relative paths in container contexts.
func StripDriveLetter(path string) string {
	if runtime.GOOS != "windows" {
		return path
	}
	
	// Check for Windows drive letter (C:, D:, etc.)
	if len(path) >= 2 && path[1] == ':' {
		// Remove drive letter and colon
		path = path[2:]
		// Remove leading slash if present
		if len(path) > 0 && (path[0] == '\\' || path[0] == '/') {
			path = path[1:]
		}
	}
	
	return path
}

// SplitPath splits a path into directory and filename components,
// handling both Unix and Windows separators.
func SplitPath(path string) (dir, file string) {
	// Normalize separators first
	path = filepath.ToSlash(path)
	
	lastSlash := strings.LastIndex(path, "/")
	if lastSlash == -1 {
		return "", path
	}
	
	return path[:lastSlash], path[lastSlash+1:]
}

// RelativeTo returns the relative path from base to target.
// Both paths should be in the same format (virtual or OS-specific).
func RelativeTo(base, target string) (string, error) {
	return filepath.Rel(base, target)
}

// ContainsPath checks if child is contained within parent directory.
// This is useful for security checks to prevent path traversal.
func ContainsPath(parent, child string) bool {
	// Clean both paths
	parent = filepath.Clean(parent)
	child = filepath.Clean(child)
	
	// Get relative path
	rel, err := filepath.Rel(parent, child)
	if err != nil {
		return false
	}
	
	// Check if relative path goes up directories
	return !strings.HasPrefix(rel, "..") && rel != ".."
}

// ValidatePathSafety checks if a path is safe to use (no path traversal).
func ValidatePathSafety(path string) bool {
	// Clean the path
	cleaned := filepath.Clean(path)
	
	// Check for path traversal attempts
	if strings.Contains(cleaned, "..") {
		return false
	}
	
	// Check for absolute paths that might escape sandbox
	if filepath.IsAbs(cleaned) {
		return false
	}
	
	return true
}

// EnsureTrailingSlash ensures a directory path ends with a slash.
// This is useful for consistent directory handling.
func EnsureTrailingSlash(path string, isVirtual bool) string {
	if path == "" {
		return path
	}
	
	separator := "/"
	if !isVirtual && runtime.GOOS == "windows" {
		separator = "\\"
	}
	
	if !strings.HasSuffix(path, separator) {
		path += separator
	}
	
	return path
}

// RemoveTrailingSlash removes trailing slashes from a path.
func RemoveTrailingSlash(path string) string {
	if path == "" || path == "/" || path == "\\" {
		return path
	}
	
	return strings.TrimRight(path, "/\\")
}