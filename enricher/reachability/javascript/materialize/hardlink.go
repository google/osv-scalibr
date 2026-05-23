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

package materialize

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// ExtractTarball decompresses and untars tarPath into destDir, stripping the
// npm-style top-level "package/" directory component.
func ExtractTarball(tarPath, destDir string) error {
	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return fmt.Errorf("mkdir dest: %w", err)
	}
	f, err := os.Open(tarPath)
	if err != nil {
		return fmt.Errorf("open tarball: %w", err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer gz.Close()
	tr := tar.NewReader(gz)

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("tar read: %w", err)
		}
		// Strip first path component (npm tarballs have a "package/" prefix).
		name := hdr.Name
		if i := strings.IndexByte(name, '/'); i >= 0 {
			name = name[i+1:]
		}
		if name == "" {
			continue
		}
		// Defend against path traversal — reject only segments equal to
		// "..", not any "..": legitimate filenames like "v1..2.js" or
		// "version..bak" contain ".." as a substring and would otherwise
		// be silently dropped, leaving the materialized package
		// incomplete and hiding their files from jelly's analysis.
		if hasParentSegment(name) {
			continue
		}
		dst := filepath.Join(destDir, name)
		// Post-join containment: defense in depth against tar-slip
		// (CWE-22). hasParentSegment catches `..` segments before the
		// join, but absolute paths, NUL bytes, or platform-specific
		// escapes might still resolve outside destDir. Reject anything
		// whose cleaned absolute form doesn't live under the cleaned
		// destDir prefix.
		cleanDest := filepath.Clean(destDir) + string(filepath.Separator)
		if !strings.HasPrefix(filepath.Clean(dst)+string(filepath.Separator), cleanDest) {
			continue
		}
		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return fmt.Errorf("mkdir %s: %w", dst, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
				return fmt.Errorf("mkdir parent: %w", err)
			}
			out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o644)
			if err != nil {
				return fmt.Errorf("create %s: %w", dst, err)
			}
			if _, err := io.Copy(out, tr); err != nil {
				out.Close()
				return fmt.Errorf("copy %s: %w", dst, err)
			}
			if err := out.Close(); err != nil {
				return err
			}
		default:
			// Ignore symlinks / special types; Jelly only needs regular files.
		}
	}
	return nil
}

// HardlinkTree replicates the contents of src at dst using hardlinks.
// Subdirectories named "node_modules" are skipped — placement decides
// where each nested package lands separately, so we don't want to
// re-link the staging tree's nested copies.
func HardlinkTree(src, dst string) error {
	return filepath.Walk(src, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return os.MkdirAll(dst, 0o755)
		}
		if info.IsDir() && info.Name() == "node_modules" {
			return filepath.SkipDir
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := os.Link(path, target); err != nil {
			// Tolerate pre-existing identical hardlinks at the destination
			// (cross-placement target collisions surface as EEXIST on the
			// second link attempt). A target that already exists with the
			// same inode is a no-op; if the inode differs, fall through and
			// report the original Link error.
			if errors.Is(err, fs.ErrExist) && sameInode(path, target) {
				return nil
			}
			return err
		}
		return nil
	})
}

// hasParentSegment reports whether any "/"-separated segment of name is
// exactly "..", which would let a tarball entry escape the destination
// directory. Substring containment is too coarse and rejects real files.
func hasParentSegment(name string) bool {
	return slices.Contains(strings.Split(name, "/"), "..")
}

// sameInode reports whether a and b refer to the same on-disk file (same
// device + inode). Used to make HardlinkTree idempotent under cross-
// placement target overlap.
func sameInode(a, b string) bool {
	sa, ea := os.Stat(a)
	sb, eb := os.Stat(b)
	if ea != nil || eb != nil {
		return false
	}
	return os.SameFile(sa, sb)
}
