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

// Package parser provides functions for parsing and writing manifest and lockfile files.
package parser

import (
	"fmt"
	"path/filepath"

	"deps.dev/util/resolve"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// ParseManifest parses a manifest file into a manifest.Manifest.
func ParseManifest(path string, rw manifest.ReadWriter) (manifest.Manifest, error) {
	fsys, path, err := fsAndPath(path)
	if err != nil {
		return nil, err
	}

	m, err := rw.Read(path, fsys)
	if err != nil {
		return nil, fmt.Errorf("error reading manifest: %w", err)
	}
	return m, nil
}

// ParseLockfile parses a lockfile file into a resolve.Graph.
func ParseLockfile(path string, rw lockfile.ReadWriter) (*resolve.Graph, error) {
	fsys, path, err := fsAndPath(path)
	if err != nil {
		return nil, err
	}

	g, err := rw.Read(path, fsys)
	if err != nil {
		return nil, fmt.Errorf("error reading lockfile: %w", err)
	}
	return g, nil
}

// WriteManifestPatches writes the patches to the manifest file.
func WriteManifestPatches(path string, m manifest.Manifest, patches []result.Patch, rw manifest.ReadWriter) error {
	fsys, _, err := fsAndPath(path)
	if err != nil {
		return err
	}

	return rw.Write(m, fsys, patches, path)
}

// WriteLockfilePatches writes the patches to the lockfile file.
func WriteLockfilePatches(path string, patches []result.Patch, rw lockfile.ReadWriter) error {
	fsys, relPath, err := fsAndPath(path)
	if err != nil {
		return err
	}

	return rw.Write(relPath, fsys, patches, path)
}

func fsAndPath(path string) (scalibrfs.FS, string, error) {
	// We need a DirFS that can potentially access files in parent directories from the file.
	// But you cannot escape the base directory of dirfs.
	// e.g. "pkg/core/pom.xml" may have a parent at "pkg/parent/pom.xml",
	// if we had fsys := scalibrfs.DirFS("pkg/core"), we can't do fsys.Open("../parent/pom.xml")
	//
	// Since we don't know ahead of time which files might be needed,
	// we must use the system root as the directory.

	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, "", err
	}

	// Get the path relative to the root (i.e. without the leading '/')
	// On Windows, we need the path relative to the drive letter,
	// which also means we can't open files across drives.
	root := filepath.VolumeName(absPath) + "/"
	relPath, err := filepath.Rel(root, absPath)
	if err != nil {
		return nil, "", err
	}
	relPath = filepath.ToSlash(relPath)

	return scalibrfs.DirFS(root), relPath, nil
}
