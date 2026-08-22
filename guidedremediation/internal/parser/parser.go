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
	"os"
	"path/filepath"
	"strings"

	"deps.dev/util/resolve"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/lockfile"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// ParseManifest parses a manifest file into a manifest.Manifest. If projectRoot
// is empty, the manifest's directory is used as the project boundary.
func ParseManifest(path string, rw manifest.ReadWriter, projectRoot string) (manifest.Manifest, error) {
	root, path, err := rootAndPath(path, projectRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	m, err := rw.Read(path, root.FS().(scalibrfs.FS))
	if err != nil {
		return nil, fmt.Errorf("error reading manifest: %w", err)
	}
	return m, nil
}

// ParseLockfile parses a lockfile file into a resolve.Graph. If projectRoot is
// empty, the lockfile's directory is used as the project boundary.
func ParseLockfile(path string, rw lockfile.ReadWriter, projectRoot string) (*resolve.Graph, error) {
	root, path, err := rootAndPath(path, projectRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()

	g, err := rw.Read(path, root.FS().(scalibrfs.FS))
	if err != nil {
		return nil, fmt.Errorf("error reading lockfile: %w", err)
	}
	return g, nil
}

// WriteManifestPatches writes the patches to the manifest file.
func WriteManifestPatches(path string, m manifest.Manifest, patches []result.Patch, rw manifest.ReadWriter, projectRoot string) error {
	root, relPath, err := rootAndPath(path, projectRoot)
	if err != nil {
		return err
	}
	defer root.Close()

	return rw.Write(m, root.FS().(scalibrfs.FS), patches, root, relPath)
}

// WriteLockfilePatches writes the patches to the lockfile file.
func WriteLockfilePatches(path string, patches []result.Patch, rw lockfile.ReadWriter, projectRoot string) error {
	root, relPath, err := rootAndPath(path, projectRoot)
	if err != nil {
		return err
	}
	defer root.Close()

	return rw.Write(relPath, root.FS().(scalibrfs.FS), patches, root, relPath)
}

func rootAndPath(path, projectRoot string) (*os.Root, string, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve path %q: %w", path, err)
	}
	root := projectRoot
	if root == "" {
		root = filepath.Dir(absPath)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return nil, "", fmt.Errorf("failed to resolve project root %q: %w", projectRoot, err)
	}
	relPath, err := filepath.Rel(root, absPath)
	if err != nil || relPath == ".." || filepath.IsAbs(relPath) || strings.HasPrefix(relPath, ".."+string(filepath.Separator)) {
		return nil, "", fmt.Errorf("path %q is outside project root %q", path, root)
	}
	rootFS, err := os.OpenRoot(root)
	if err != nil {
		return nil, "", fmt.Errorf("failed to open project root %q: %w", root, err)
	}

	return rootFS, filepath.ToSlash(relPath), nil
}
