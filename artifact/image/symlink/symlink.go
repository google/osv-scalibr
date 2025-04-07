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

// Package symlink provides symlink-related util functions for container extraction.
package symlink

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/log"
	"github.com/google/uuid"
)

// RemoveObsoleteSymlinks removes symlinks that point to a destination file or directory path that
// does not exist. Note: There are three terms used in this function: symlink, target link, and
// destination file.
//
//	symlink: Refers to the symlink file itself.
//	target link: The link stored in a symlink file that points to another file (or symlink).
//	destination file: The last file pointed to by a symlink. That is, if there is a chain of
//	  symlinks, the destination file is the file pointed to by the last symlink.
//
// Example: In this file system, the symlink, sym3, points to a destination file that doesn't exist
//
//	       (b.txt). This function would remove the sym3.txt file.
//	root
//	  dir1
//	    a.txt
//	    sym1.txt -> ../dir2/sym2.txt
//	  dir2
//	    sym2.txt -> ../dir1/a.txt
//	    sym3.txt -> ../dir1/b.txt (would be removed since b.txt does not exist)
func RemoveObsoleteSymlinks(root string) error {
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warnf("Failed to walk directory %q: %v", path, err)
			return fmt.Errorf("failed to walk directory %q: %w", path, err)
		}

		if (d.Type() & fs.ModeType) != fs.ModeSymlink {
			return nil
		}

		// Gets the target link from the symlink file.
		linkTarget, err := os.Readlink(path)
		if err != nil {
			log.Warnf("Failed to read target of symlink %q: %v", path, err)
			return fmt.Errorf("failed to read target of symlink %q: %w", path, err)
		}

		// Relative symlinks must be resolved in order to determine if the destination exists.
		if !filepath.IsAbs(linkTarget) {
			linkTarget = filepath.Join(filepath.Dir(path), linkTarget)
		}

		// The destination exists, so we can return and go on to the next path.
		if _, err = os.Stat(linkTarget); err == nil {
			return nil
		}

		// Destination doesn't exist so remove symlink file.
		err = os.Remove(path)
		if err != nil {
			log.Warnf("Failed to remove symlink %q: %v", path, err)
			return err
		}
		log.Infof("Removed symlink %q", path)
		return nil
	})
	return err
}

// ResolveInterLayerSymlinks resolves absolute and relative symlinks in a layer sub-directory with
// a given layer digest by redirecting the symlink target path to point to the SQUASHED layer's
// symlink target path if it exists.
//
// The structure of the layered directory before resolving symlinks is as follows:
//
//	root
//	  layer1digest
//	    dir1
//	      sample.txt
//	  layer2digest
//	    dir2
//	      relative-symlink.txt -> ../sample.txt    (notice how ../sample.txt wouldn't be found due to the layering approach)
//	      absolute-symlink.txt -> /dir1/sample.txt (the /dir1/sample.txt target file also wouldn't be found)
//	  SQUASHED
//	    dir1
//	      sample.txt
//	    dir2
//	      relative-symlink.txt -> /root/SQUASHED/dir1/sample.txt
//	      absolute-symlink.txt -> /root/SQUASHED/dir1/sample.txt
//
// After resolving the layer with layer digest of "layer2digest", the file system is as follows:
//
//	root
//	  layer1digest
//	    dir1
//	      sample.txt
//	  layer2digest
//	    dir2
//	      relative-symlink.txt -> /root/SQUASHED/dir2/relative-symlink.txt
//	      absolute-symlink.txt -> /root/SQUASHED/dir2/relative-symlink.txt
//	  SQUASHED
//	    dir1
//	      sample.txt
//	    dir2
//	      relative-symlink.txt -> /root/SQUASHED/dir1/sample.txt
//	      absolute-symlink.txt -> /root/SQUASHED/dir1/sample.txt
func ResolveInterLayerSymlinks(root, layerDigest, squashedImageDirectory string) error {
	layerPath := filepath.Join(root, strings.ReplaceAll(layerDigest, ":", "-"))

	// Walk through each symlink in the layer, convert to absolute symlink, then resolve cross layer
	// symlinks.
	err := filepath.WalkDir(layerPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			log.Warnf("Failed to walk directory %q: %v", path, err)
			return fmt.Errorf("failed to walk directory %q: %w", path, err)
		}

		// Skip anything that isn't a symlink.
		if (d.Type() & fs.ModeType) != fs.ModeSymlink {
			return nil
		}

		if err = resolveSingleSymlink(root, path, layerPath, squashedImageDirectory); err != nil {
			return fmt.Errorf("failed to resolve symlink %q: %w", path, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk directory %q: %w", layerPath, err)
	}
	return nil
}

// resolveSingleSymlink resolves a single symlink by checking if the target path of the symlink
// exists in the squashed layer. If it does, then the symlink is updated to point to the target path
// in the squashed layer. This relies on the squashed layer having all of its symlinks resolved
// properly.
func resolveSingleSymlink(root, symlink, layerPath, resolvedDirectory string) error {
	targetPath, err := os.Readlink(symlink)
	if err != nil {
		return fmt.Errorf("failed to read symlink %q: %w", symlink, err)
	}

	if !filepath.IsAbs(targetPath) {
		targetPath = removeLayerPathPrefix(filepath.Join(filepath.Dir(symlink), targetPath), layerPath)
	} else {
		targetPath = removeLayerPathPrefix(targetPath, layerPath)
	}

	targetPathInSquashedLayer := filepath.Join(root, resolvedDirectory, targetPath)

	// Remove the existing symlink.
	if err := os.Remove(symlink); err != nil && !os.IsNotExist(err) {
		log.Warnf("Failed to remove symlink %q: %v", symlink, err)
		return fmt.Errorf("failed to remove symlink %q: %w", symlink, err)
	}

	// If target path does not exist, then squashed layer did not contain the file that the symlink
	// pointed to and will not be included in final file-system for SCALIBR to scan.
	if _, err = os.Stat(targetPathInSquashedLayer); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("failed to get status of file %q: %w", targetPathInSquashedLayer, err)
	}

	// Recreate the symlink with the new destination path.
	if err := os.Symlink(targetPathInSquashedLayer, symlink); err != nil {
		log.Warnf("Failed to create symlink %q: %v", symlink, err)
		return fmt.Errorf("failed to create symlink %q: %w", symlink, err)
	}
	return nil
}

func removeLayerPathPrefix(path, layerPath string) string {
	return filepath.Clean(strings.TrimPrefix(path, layerPath))
}

// TargetOutsideRoot checks if the target of a symlink points outside of the root directory of that
// symlink's path.
// For example, if a symlink with path `a/symlink.txt“ points to “../../file.text“, then
// this function would return true because the target file is outside of the root directory.
func TargetOutsideRoot(path, target string) bool {
	// Create a marker directory as root to check if the target path is outside of the root directory.
	markerDir := uuid.New().String()
	if filepath.IsAbs(target) {
		// Absolute paths may still point outside of the root directory.
		// e.g. "/../file.txt"
		markerTarget := filepath.Join(markerDir, target)
		return !strings.Contains(markerTarget, markerDir)
	}

	markerTargetAbs := filepath.Join(markerDir, filepath.Dir(path), target)
	return !strings.Contains(markerTargetAbs, markerDir)
}
