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

package mavenutil

import (
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/log"
)

// IsPOMFile returns true if the given path is a Maven POM file.
// It matches "pom.xml", "pom-*.xml", and "*-pom.xml".
func IsPOMFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	if base == "pom.xml" {
		return true
	}
	if !strings.HasSuffix(base, ".xml") {
		return false
	}
	name := strings.TrimSuffix(base, ".xml")
	return strings.HasPrefix(name, "pom-") || strings.HasSuffix(name, "-pom")
}

// TopLevelPOMs returns the paths of the POM files directly inside dir.
func TopLevelPOMs(fsys scalibrfs.FS, dir string) ([]string, error) {
	stat, err := fsys.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to stat %q: %w", dir, err)
	}
	if !stat.IsDir() {
		return nil, fmt.Errorf("%q is not a directory", dir)
	}
	entries, err := fsys.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %q: %w", dir, err)
	}
	var paths []string
	for _, entry := range entries {
		if !entry.IsDir() && IsPOMFile(entry.Name()) {
			paths = append(paths, filepath.ToSlash(filepath.Join(dir, entry.Name())))
		}
	}
	return paths, nil
}

// LocalModuleDirPOMs returns the top-level POM files of dirs, which are relative to the root of
// fsys. Projects that a build installs from outside the manifest's module tree, such as a git
// submodule, are discovered from them. A directory that is missing, such as a submodule that was
// not checked out, or that lies outside the root is skipped with a warning.
func LocalModuleDirPOMs(fsys scalibrfs.FS, dirs []string) []string {
	var paths []string
	for _, dir := range dirs {
		dir = filepath.ToSlash(filepath.Clean(dir))
		if dir == "." {
			continue // The root is discovered as part of the project.
		}
		if !fs.ValidPath(dir) {
			log.Warnf("Ignoring local module directory %q outside the root", dir)
			continue
		}
		dirPOMs, err := TopLevelPOMs(fsys, dir)
		if err != nil {
			log.Warnf("Ignoring local module directory: %v", err)
			continue
		}
		paths = append(paths, dirPOMs...)
	}
	return paths
}
