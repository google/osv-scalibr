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

package image

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scalibr/artifact/image/require"
)

// TestFromTarball_FileRequirerFiltersRegularFiles verifies that a Config with a
// FileRequirer materializes only the regular files it requires, while keeping
// directories so the virtual filesystem stays navigable.
func TestFromTarball_FileRequirerFiltersRegularFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"dir1/bar.txt"})

	img, err := FromTarball(filepath.Join(testdataDir, "multiple-files.tar"), cfg)
	if err != nil {
		t.Fatalf("FromTarball returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()
	fsys := img.FS()

	// The required regular file is materialized with its content.
	if got, err := fs.ReadFile(fsys, "dir1/bar.txt"); err != nil {
		t.Errorf("required file dir1/bar.txt missing: %v", err)
	} else if string(got) != "bar\n" {
		t.Errorf("dir1/bar.txt content = %q, want %q", got, "bar\n")
	}

	// Regular files no requirer wants are not materialized.
	for _, p := range []string{"foo.txt", "dir1/baz.txt"} {
		if _, err := fs.Stat(fsys, p); err == nil {
			t.Errorf("non-required file %q was materialized, want absent", p)
		}
	}

	// Directories are always kept so the tree remains navigable.
	if fi, err := fs.Stat(fsys, "dir1"); err != nil {
		t.Errorf("dir1 should remain present: %v", err)
	} else if !fi.IsDir() {
		t.Errorf("dir1 should be a directory")
	}
}

// TestFromTarball_NilFileRequirerKeepsAllFiles verifies the default (nil
// requirer / FileRequirerAll) is unchanged: every file is materialized.
func TestFromTarball_NilFileRequirerKeepsAllFiles(t *testing.T) {
	cfg := DefaultConfig()
	cfg.FileRequirer = nil // validateConfig defaults this to FileRequirerAll

	img, err := FromTarball(filepath.Join(testdataDir, "multiple-files.tar"), cfg)
	if err != nil {
		t.Fatalf("FromTarball returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()
	fsys := img.FS()

	for _, p := range []string{"foo.txt", "dir1/bar.txt", "dir1/baz.txt"} {
		if _, err := fs.Stat(fsys, p); err != nil {
			t.Errorf("file %q should be materialized with the default requirer: %v", p, err)
		}
	}
}

// TestFromV1Image_FileRequirerKeepsDirectoryWhiteouts verifies that filtering does
// not drop directory whiteouts. A whiteout is a 0-byte regular file whose
// de-whiteouted path (the deleted directory) is not in the required set, so gating
// it on the requirer would skip it and leak the deleted file back into the merged
// filesystem.
func TestFromV1Image_FileRequirerKeepsDirectoryWhiteouts(t *testing.T) {
	// Lower layer adds dir1/keep.txt; upper layer deletes all of dir1 via a
	// ".wh.dir1" whiteout.
	lower := layerFromTarEntries(t, []*tarEntry{
		{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "dir1/", Mode: 0755}},
		{
			Header: &tar.Header{Typeflag: tar.TypeReg, Name: "dir1/keep.txt", Mode: 0644, Size: int64(len("keep\n"))},
			Data:   bytes.NewBufferString("keep\n"),
		},
	})
	upper := layerFromTarEntries(t, []*tarEntry{
		{Header: &tar.Header{Typeflag: tar.TypeReg, Name: ".wh.dir1", Mode: 0644, Size: 0}},
	})

	img1, err := mutate.AppendLayers(empty.Image, lower, upper)
	if err != nil {
		t.Fatalf("mutate.AppendLayers: %v", err)
	}

	cfg := DefaultConfig()
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"dir1/keep.txt"})

	img, err := FromV1Image(img1, cfg)
	if err != nil {
		t.Fatalf("FromV1Image returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()

	// The whiteout must survive filtering, so the deleted file is absent.
	if _, err := fs.Stat(img.FS(), "dir1/keep.txt"); err == nil {
		t.Errorf("dir1/keep.txt was not deleted; directory whiteout was dropped by the requirer")
	}
}

// TestFromV1Image_FileRequirerMaterializesSymlinkTarget verifies that when a
// required path is a symlink, the regular file it points to is also materialized
// even though the target itself is not in the required set. Otherwise reading the
// required path through the symlink would dangle.
func TestFromV1Image_FileRequirerMaterializesSymlinkTarget(t *testing.T) {
	tests := []struct {
		name    string
		linkTo  string // Linkname of etc/os-release.
		require []string
	}{
		{
			name:    "absolute target",
			linkTo:  "/usr/lib/os-release",
			require: []string{"etc/os-release"},
		},
		{
			name:    "relative target",
			linkTo:  "../usr/lib/os-release",
			require: []string{"etc/os-release"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			layer := layerFromTarEntries(t, []*tarEntry{
				{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "etc/", Mode: 0755}},
				{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "usr/lib/", Mode: 0755}},
				{
					Header: &tar.Header{Typeflag: tar.TypeReg, Name: "usr/lib/os-release", Mode: 0644, Size: int64(len("ID=debian\n"))},
					Data:   bytes.NewBufferString("ID=debian\n"),
				},
				{Header: &tar.Header{Typeflag: tar.TypeSymlink, Name: "etc/os-release", Linkname: tc.linkTo, Mode: 0777}},
			})
			img1, err := mutate.AppendLayers(empty.Image, layer)
			if err != nil {
				t.Fatalf("mutate.AppendLayers: %v", err)
			}

			cfg := DefaultConfig()
			cfg.FileRequirer = require.NewFileRequirerPaths(tc.require)
			img, err := FromV1Image(img1, cfg)
			if err != nil {
				t.Fatalf("FromV1Image returned error: %v", err)
			}
			defer func() { _ = img.CleanUp() }()

			// Reading the required path through the symlink returns the target content.
			if got, err := fs.ReadFile(img.FS(), "etc/os-release"); err != nil {
				t.Errorf("read required-via-symlink etc/os-release: %v", err)
			} else if string(got) != "ID=debian\n" {
				t.Errorf("etc/os-release content = %q, want %q", got, "ID=debian\n")
			}
		})
	}
}

// TestFromV1Image_FileRequirerFollowsSymlinkChain verifies that a chain of
// symlinks (a -> b -> regular) is followed so the terminal regular file is
// materialized.
func TestFromV1Image_FileRequirerFollowsSymlinkChain(t *testing.T) {
	layer := layerFromTarEntries(t, []*tarEntry{
		{
			Header: &tar.Header{Typeflag: tar.TypeReg, Name: "c.txt", Mode: 0644, Size: int64(len("c\n"))},
			Data:   bytes.NewBufferString("c\n"),
		},
		{Header: &tar.Header{Typeflag: tar.TypeSymlink, Name: "b.txt", Linkname: "/c.txt", Mode: 0777}},
		{Header: &tar.Header{Typeflag: tar.TypeSymlink, Name: "a.txt", Linkname: "/b.txt", Mode: 0777}},
	})
	img1, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("mutate.AppendLayers: %v", err)
	}

	cfg := DefaultConfig()
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"a.txt"})
	img, err := FromV1Image(img1, cfg)
	if err != nil {
		t.Fatalf("FromV1Image returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()

	if got, err := fs.ReadFile(img.FS(), "a.txt"); err != nil {
		t.Errorf("read required-via-symlink-chain a.txt: %v", err)
	} else if string(got) != "c\n" {
		t.Errorf("a.txt content = %q, want %q", got, "c\n")
	}
}

// TestFromV1Image_FileRequirerMaterializesTargetInUpperLayer verifies that the
// symlink target is materialized even when it lives in a layer processed before
// the symlink's layer. Layers are processed latest-first, so a target in an
// upper layer is seen before the lower-layer symlink that requires it; resolving
// it requires more than one pass.
func TestFromV1Image_FileRequirerMaterializesTargetInUpperLayer(t *testing.T) {
	// Lower layer holds the symlink; upper layer holds its target.
	lower := layerFromTarEntries(t, []*tarEntry{
		{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "etc/", Mode: 0755}},
		{Header: &tar.Header{Typeflag: tar.TypeSymlink, Name: "etc/os-release", Linkname: "/usr/lib/os-release", Mode: 0777}},
	})
	upper := layerFromTarEntries(t, []*tarEntry{
		{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "usr/lib/", Mode: 0755}},
		{
			Header: &tar.Header{Typeflag: tar.TypeReg, Name: "usr/lib/os-release", Mode: 0644, Size: int64(len("ID=debian\n"))},
			Data:   bytes.NewBufferString("ID=debian\n"),
		},
	})
	img1, err := mutate.AppendLayers(empty.Image, lower, upper)
	if err != nil {
		t.Fatalf("mutate.AppendLayers: %v", err)
	}

	cfg := DefaultConfig()
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"etc/os-release"})
	img, err := FromV1Image(img1, cfg)
	if err != nil {
		t.Fatalf("FromV1Image returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()

	if got, err := fs.ReadFile(img.FS(), "etc/os-release"); err != nil {
		t.Errorf("read required-via-symlink etc/os-release: %v", err)
	} else if string(got) != "ID=debian\n" {
		t.Errorf("etc/os-release content = %q, want %q", got, "ID=debian\n")
	}
}

// TestFromV1Image_FileRequirerDoesNotMaterializeUnrequiredSymlinkTarget verifies
// that target materialization only follows symlinks that are themselves required.
// A symlink no extractor wants must not pull its target into the content store.
func TestFromV1Image_FileRequirerDoesNotMaterializeUnrequiredSymlinkTarget(t *testing.T) {
	layer := layerFromTarEntries(t, []*tarEntry{
		{Header: &tar.Header{Typeflag: tar.TypeDir, Name: "usr/lib/", Mode: 0755}},
		{
			Header: &tar.Header{Typeflag: tar.TypeReg, Name: "usr/lib/os-release", Mode: 0644, Size: int64(len("ID=debian\n"))},
			Data:   bytes.NewBufferString("ID=debian\n"),
		},
		{Header: &tar.Header{Typeflag: tar.TypeSymlink, Name: "etc/os-release", Linkname: "/usr/lib/os-release", Mode: 0777}},
		{
			Header: &tar.Header{Typeflag: tar.TypeReg, Name: "wanted.txt", Mode: 0644, Size: int64(len("w\n"))},
			Data:   bytes.NewBufferString("w\n"),
		},
	})
	img1, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("mutate.AppendLayers: %v", err)
	}

	cfg := DefaultConfig()
	// Require only an unrelated file; the symlink etc/os-release is not required.
	cfg.FileRequirer = require.NewFileRequirerPaths([]string{"wanted.txt"})
	img, err := FromV1Image(img1, cfg)
	if err != nil {
		t.Fatalf("FromV1Image returned error: %v", err)
	}
	defer func() { _ = img.CleanUp() }()

	// The target of the non-required symlink must not be materialized.
	if _, err := fs.Stat(img.FS(), "usr/lib/os-release"); err == nil {
		t.Errorf("usr/lib/os-release was materialized via a non-required symlink, want absent")
	}
}

// layerFromTarEntries builds a single image layer from the given tar entries.
func layerFromTarEntries(t *testing.T, entries []*tarEntry) v1.Layer {
	t.Helper()

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)
	for _, e := range entries {
		if err := w.WriteHeader(e.Header); err != nil {
			t.Fatalf("WriteHeader(%s): %v", e.Header.Name, err)
		}
		if e.Data != nil {
			if _, err := io.Copy(w, e.Data); err != nil {
				t.Fatalf("writing content for %s: %v", e.Header.Name, err)
			}
		}
	}
	w.Close()

	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBuffer(buf.Bytes())), nil
	})
	if err != nil {
		t.Fatalf("tarball.LayerFromOpener: %v", err)
	}
	return layer
}
