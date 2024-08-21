// Copyright 2024 Google LLC
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

// Package fs provides a virtual filesystem interface for SCALIBR scans and related helper functions.
package fs

import (
	"io/fs"
	"os"
	"path/filepath"
)

// FS is a filesystem interface that allows the opening of files, reading of
// directories, and performing stat on files.
//
// FS implementations may return ErrNotImplemented for `Open`, `ReadDir` and `Stat`.
// Extractor implementations must decide whether the error is fatal or can be ignored.
//
// FS implementations MUST implement io.ReaderAt for opened files to enable random access.
type FS interface {
	fs.FS
	fs.ReadDirFS
	fs.StatFS
}

// ScanRoot defines a root directory to start a scan from.
// mounted to a local dir.
type ScanRoot struct {
	// A virtual filesystem for file access, rooted at the scan root.
	FS FS
	// The path of the scan root. Empty if this is a virtual filesystem and the
	// scanning environment doesn't support the DirectFS requirement.
	Path string
}

// IsVirtual returns true if the scan root represents the root of a virtual
// filesystem, i.e. one with no real location on the disk of the scanned host.
func (r *ScanRoot) IsVirtual() bool {
	return r.Path == ""
}

// WithAbsolutePath returns a copy of the ScanRoot with the Path
// set an absolute path.
func (r *ScanRoot) WithAbsolutePath() (*ScanRoot, error) {
	if r.Path == "" {
		// Virtual-only filesystem
		return &ScanRoot{FS: r.FS, Path: r.Path}, nil
	}
	absroot, err := filepath.Abs(r.Path)
	if err != nil {
		return nil, err
	}
	return &ScanRoot{FS: r.FS, Path: absroot}, nil
}

// DirFS returns an FS implementation that accesses the real filesystem at the given root.
func DirFS(root string) FS {
	return os.DirFS(root).(FS)
}

// RealFSScanRoots returns a one-element ScanRoot array representing the given
// root path on the real filesystem SCALIBR is running on.
func RealFSScanRoots(path string) []*ScanRoot {
	return []*ScanRoot{RealFSScanRoot(path)}
}

// RealFSScanRoot returns a ScanRoot array the given root path on the real
// filesystem SCALIBR is running on.
func RealFSScanRoot(path string) *ScanRoot {
	return &ScanRoot{FS: DirFS(path), Path: path}
}
