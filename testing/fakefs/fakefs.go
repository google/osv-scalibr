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

// Package fakefs provides a fake file system implementation for testing.
package fakefs

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	scalibrfs "github.com/google/osv-scalibr/fs"
	"golang.org/x/tools/txtar"
)

// FileModifier allows mutating a file (e.g., compressing data, changing mode)
type FileModifier func(name string, f *fstest.MapFile) error

// PrepareFS parses a txtar string into a mock filesystem.
// Optional modifiers can be provided to intercept and modify files (e.g., compression).
// Files ending in "/" in the txtar archive are treated as empty directories.
func PrepareFS(txt string, modifiers ...FileModifier) (scalibrfs.FS, error) {
	archive := txtar.Parse([]byte(txt))
	mfs := make(fstest.MapFS)

	for _, tf := range archive.Files {
		// If it ends in /, it's a directory.
		if cut, ok := strings.CutSuffix(tf.Name, "/"); ok {
			mfs[cut] = &fstest.MapFile{Mode: fs.ModeDir | 0755}
			continue
		}

		mf := &fstest.MapFile{
			Data: tf.Data,
			Mode: 0644,
		}

		for _, mod := range modifiers {
			if err := mod(tf.Name, mf); err != nil {
				return nil, err
			}
		}

		mfs[tf.Name] = mf
	}

	return mfs, nil
}

// TarGzModifier parses the content of a .tar.gz file like a nested txtar
// and builds the tarball content, Example:
//
//	-- example.tar.gz --
//	== FILE1.ext ==
//	content
//	== FILE2.ext ==
//	content
func TarGzModifier(name string, f *fstest.MapFile) error {
	if !strings.HasSuffix(name, ".tar.gz") {
		return nil
	}

	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	// == are used to differentiate between tar.gz and txtar control chars,
	// convert them into -- so that txtar.Parse can parse them
	innerData := bytes.ReplaceAll(f.Data, []byte("=="), []byte("--"))
	archive := txtar.Parse(innerData)
	for _, tf := range archive.Files {
		if err := tw.WriteHeader(&tar.Header{Name: tf.Name, Mode: 0600, Size: int64(len(tf.Data))}); err != nil {
			return err
		}
		if _, err := tw.Write(tf.Data); err != nil {
			return err
		}
	}

	tw.Close()
	gw.Close()

	f.Data = buf.Bytes()
	return nil
}

// SimLinkModifier dynamically loads a file content from a specific location, example:
//
//	-- /path/to/file --
//	-> testdata/file
func SimLinkModifier(name string, f *fstest.MapFile) error {
	after, ok := bytes.CutPrefix(f.Data, []byte("-> "))
	if !ok {
		return nil
	}
	fixturePath := strings.TrimSpace(string(after))
	b, err := os.ReadFile(fixturePath)
	if err != nil {
		return err
	}
	f.Data = b
	return nil
}

// CopyTestData copies the directory tree rooted at srcDir into a new temporary
// directory created via tb.TempDir() and returns the path of the copy.
//
// Symlinks to files and directories (including srcDir itself) are followed and
// copied as regular files and directories, so the copy can be opened with
// os.Root even when the test environment provides fixtures as symlinks that
// point outside srcDir. Unlike os.CopyFS, which recreates symlinks as symlinks,
// the copy contains no symlinks. Copied files are made owner-writable.
func CopyTestData(tb testing.TB, srcDir string) string {
	tb.Helper()
	dstDir := tb.TempDir()
	if err := copyDirDeref(srcDir, dstDir, map[string]bool{}); err != nil {
		tb.Fatalf("CopyTestData(%q): %v", srcDir, err)
	}
	return dstDir
}

// copyDirDeref recursively copies src into dst, following symlinks. ancestors
// holds the resolved paths of the directories currently being copied and is
// used to detect symlink cycles.
func copyDirDeref(src, dst string, ancestors map[string]bool) error {
	resolved, err := filepath.EvalSymlinks(src)
	if err != nil {
		return err
	}
	if ancestors[resolved] {
		return fmt.Errorf("symlink cycle at %q", src)
	}
	ancestors[resolved] = true
	defer delete(ancestors, resolved)

	if err := os.MkdirAll(dst, 0755); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dst, e.Name())
		info, err := os.Stat(s) // Follows symlinks.
		if err != nil {
			return err
		}
		switch {
		case info.IsDir():
			if err := copyDirDeref(s, d, ancestors); err != nil {
				return err
			}
		case info.Mode().IsRegular():
			data, err := os.ReadFile(s)
			if err != nil {
				return err
			}
			if err := os.WriteFile(d, data, 0644|info.Mode().Perm()&0111); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported file type %v at %q", info.Mode().Type(), s)
		}
	}
	return nil
}

// OutsideFileContent is the content of the file that the symlink created by
// CreateSymlinkEscapeFixture points to.
const OutsideFileContent = "outside-secret"

// CreateSymlinkEscapeFixture creates a scan root directory inside tb.TempDir()
// containing a symlink at linkRelPath (a local, slash-separated path) that
// points to a file outside the scan root. The file contains OutsideFileContent.
// It returns the scan root and the path of the outside file.
//
// The test is skipped if symlinks can't be created on Windows.
func CreateSymlinkEscapeFixture(tb testing.TB, linkRelPath string) (scanRoot, outsidePath string) {
	tb.Helper()
	if !filepath.IsLocal(filepath.FromSlash(linkRelPath)) {
		tb.Fatalf("CreateSymlinkEscapeFixture: linkRelPath %q is not a local path", linkRelPath)
	}
	parentDir := tb.TempDir()
	outsidePath = filepath.Join(parentDir, "outside.txt")
	if err := os.WriteFile(outsidePath, []byte(OutsideFileContent), 0600); err != nil {
		tb.Fatalf("os.WriteFile(%q): %v", outsidePath, err)
	}
	scanRoot = filepath.Join(parentDir, "root")
	linkPath := filepath.Join(scanRoot, filepath.FromSlash(linkRelPath))
	if err := os.MkdirAll(filepath.Dir(linkPath), 0755); err != nil {
		tb.Fatalf("os.MkdirAll(%q): %v", filepath.Dir(linkPath), err)
	}
	if err := os.Symlink(outsidePath, linkPath); err != nil {
		if runtime.GOOS == "windows" {
			tb.Skipf("symlink creation may require additional privileges on Windows: %v", err)
		}
		tb.Fatalf("os.Symlink(%q, %q): %v", outsidePath, linkPath, err)
	}
	return scanRoot, outsidePath
}
