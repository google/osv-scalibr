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

package unpack_test

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"archive/tar"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/osv-scalibr/artifact/image/require"
	"github.com/google/osv-scalibr/artifact/image/unpack"
)

type contentAndMode struct {
	content string
	mode    fs.FileMode
}

func TestNewUnpacker(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *unpack.UnpackerConfig
		want    *unpack.Unpacker
		wantErr error
	}{{
		name: "missing_SymlinkResolution",
		cfg: &unpack.UnpackerConfig{
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			Requirer:           &require.FileRequirerAll{},
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "missing_SymlinkErrStrategy",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution: unpack.SymlinkRetain,
			Requirer:          &require.FileRequirerAll{},
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "missing_Requirer",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "0_MaxFileBytes_bytes",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			MaxPass:            100,
			MaxFileBytes:       0,
			Requirer:           &require.FileRequirerAll{},
		},
		want: &unpack.Unpacker{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			MaxPass:            100,
			MaxSizeBytes:       1024 * 1024 * 1024 * 1024, // 1TB
			Requirer:           &require.FileRequirerAll{},
		},
	}, {
		name: "all_fields_populated",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			MaxPass:            100,
			MaxFileBytes:       1024 * 1024 * 5, // 5MB
			Requirer:           &require.FileRequirerAll{},
		},
		want: &unpack.Unpacker{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			MaxPass:            100,
			MaxSizeBytes:       1024 * 1024 * 5, // 5MB
			Requirer:           &require.FileRequirerAll{},
		},
	}, {
		name: "default_config",
		cfg:  unpack.DefaultUnpackerConfig(),
		want: &unpack.Unpacker{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			MaxPass:            3,
			MaxSizeBytes:       unpack.DefaultMaxFileBytes,
			Requirer:           &require.FileRequirerAll{},
		},
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := unpack.NewUnpacker(tc.cfg)
			if !cmp.Equal(err, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("NewUnpacker(%+v) error: got %v, want %v\n", tc.cfg, err, tc.wantErr)
			}

			opts := []cmp.Option{
				cmp.AllowUnexported(unpack.Unpacker{}),
			}
			if diff := cmp.Diff(tc.want, got, opts...); diff != "" {
				t.Fatalf("NewUnpacker(%+v) returned unexpected diff (-want +got):\n%s", tc.cfg, diff)
			}
		})
	}
}

func TestUnpackSquashed(t *testing.T) {
	if runtime.GOOS != "linux" {
		// TODO(b/366163334): Make tests work on Mac and Windows.
		return
	}

	tests := []struct {
		name    string
		cfg     *unpack.UnpackerConfig
		dir     string
		image   v1.Image
		want    map[string]contentAndMode
		wantErr error
	}{{
		name:    "missing directory",
		cfg:     unpack.DefaultUnpackerConfig(),
		dir:     "",
		image:   empty.Image,
		wantErr: cmpopts.AnyError,
	}, {
		name:    "nil image",
		cfg:     unpack.DefaultUnpackerConfig(),
		dir:     t.TempDir(),
		image:   nil,
		wantErr: cmpopts.AnyError,
	}, {
		name:  "empty image",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   t.TempDir(),
		image: empty.Image,
		want:  map[string]contentAndMode{},
	}, {
		name:  "single layer image",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want: map[string]contentAndMode{
			"sample.txt":        {content: "sample text file\n", mode: fs.FileMode(0644)},
			"larger-sample.txt": {content: strings.Repeat("sample text file\n", 400), mode: fs.FileMode(0644)},
		},
	}, {
		name:  "large files are skipped",
		cfg:   unpack.DefaultUnpackerConfig().WithMaxFileBytes(1024),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want: map[string]contentAndMode{
			"sample.txt": {content: "sample text file\n", mode: fs.FileMode(0644)},
		},
	}, {
		name:  "image with restricted file permissions",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "permissions.tar")),
		want: map[string]contentAndMode{
			"sample.txt": {content: "sample text file\n", mode: fs.FileMode(0600)},
		},
	}, {
		name: "image_with_symlinks",
		cfg:  unpack.DefaultUnpackerConfig().WithMaxPass(1),
		dir: func() string {
			// Create an inner directory to unpack in and an outer directory to test if symlinks try pointing to it.
			// This test checks that symlinks that attempt to point outside the unpack directory are removed.
			dir := t.TempDir()
			innerDir := filepath.Join(dir, "innerdir")
			err := os.Mkdir(innerDir, 0777)
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			_ = os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("some secret\n"), 0644)
			return innerDir
		}(),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlinks.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"):                  {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/chain-symlink.txt"):                     {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/relative-dot-symlink.txt"):              {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/relative-symlink.txt"):                  {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):                            {content: "sample text\n", mode: fs.FileMode(0644)},
			filepath.FromSlash("dir2/dir3/absolute-chain-symlink.txt"):       {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir2/dir3/absolute-subfolder-symlink.txt"):   {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir2/dir3/absolute-symlink-inside-root.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir2/dir3/relative-subfolder-symlink.txt"):   {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
		},
	}, {
		name: "image_with_absolute_path_symlink_but_only_the_symlink_is_required",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(2).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/absolute-symlink.txt"),
			}),
		),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlinks.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):           {content: "sample text\n", mode: fs.FileMode(0644)},
		},
	}, {
		name: "image_with_a_chain_of_symlinks_but_only_the_first_symlink_is_required",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(2).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/chain-symlink.txt"),
			}),
		),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlinks.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/chain-symlink.txt"):    {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):           {content: "sample text\n", mode: fs.FileMode(0644)},
		},
	}, {
		name: "image_with_absolute_path_symlink,_only_the_symlink_is_required,_but_there_were_not_enough_passes_to_resolve_the_symlink",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(1).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/chain-symlink.txt"),
			}),
		),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlinks.tar")),
		want:  map[string]contentAndMode{},
	}, {
		name: "image_built_from_scratch_(not_through_a_tool_like_Docker)",
		cfg:  unpack.DefaultUnpackerConfig().WithMaxPass(1),
		dir:  t.TempDir(),
		image: mustNewSquashedImage(t, map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"):     {"some text", 0600},
			filepath.FromSlash("another/file.json"): {"some other text", 0600},
		}),
		want: map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"):     {content: "some text", mode: fs.FileMode(0600)},
			filepath.FromSlash("another/file.json"): {content: "some other text", mode: fs.FileMode(0600)},
		},
	}, {
		name: "only_some_files_are_required",
		cfg:  unpack.DefaultUnpackerConfig().WithRequirer(require.NewFileRequirerPaths([]string{"some/file.txt"})),
		dir:  t.TempDir(),
		image: mustNewSquashedImage(t, map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"):     {"some text", 0600},
			filepath.FromSlash("another/file.json"): {"some other text", 0600},
		}),
		want: map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"): {content: "some text", mode: fs.FileMode(0600)},
		},
	}, {
		name:  "dangling symlinks are removed",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   t.TempDir(),
		image: mustImageFromPath(t, filepath.Join("testdata", "dangling-symlinks.tar")),
		want:  map[string]contentAndMode{},
	}, {
		name:    "return error for unimplemented symlink ignore resolution strategy",
		cfg:     unpack.DefaultUnpackerConfig().WithSymlinkResolution(unpack.SymlinkIgnore),
		dir:     t.TempDir(),
		image:   mustImageFromPath(t, filepath.Join("testdata", "dangling-symlinks.tar")),
		wantErr: cmpopts.AnyError,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			defer os.RemoveAll(tc.dir)
			u := mustNewUnpacker(t, tc.cfg)
			gotErr := u.UnpackSquashed(tc.dir, tc.image)
			if !cmp.Equal(gotErr, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Unpacker{%+v}.UnpackSquashed(%q, %q) error: got %v, want %v\n", tc.cfg, tc.dir, tc.image, gotErr, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			got := mustReadDir(t, tc.dir)
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(contentAndMode{})); diff != "" {
				t.Fatalf("Unpacker{%+v}.UnpackSquashed(%q, %q) returned unexpected diff (-want +got):\n%s", tc.cfg, tc.dir, tc.image, diff)
			}
		})
	}
}

func TestUnpackSquashedFromTarball(t *testing.T) {
	if runtime.GOOS != "linux" {
		// TODO(b/366163334): Make tests work on Mac and Windows.
		return
	}

	tests := []struct {
		name       string
		cfg        *unpack.UnpackerConfig
		dir        string
		tarEntries []tarEntry
		want       map[string]contentAndMode
		wantErr    error
	}{
		{
			name: "os.Root_fails_when_writing_files_outside_base_directory_due_to_long_symlink_target",
			cfg: unpack.DefaultUnpackerConfig().WithRequirer(require.NewFileRequirerPaths([]string{
				"/usr/share/doc/a/copyright",
				"/usr/share/doc/b/copyright",
				"/usr/share/doc/c/copyright",
			})),
			dir: t.TempDir(),
			tarEntries: []tarEntry{
				{
					Header: &tar.Header{
						Name: "/escape/poc.txt",
						Mode: 0777,
						Size: int64(len("👻")),
					},
					Data: bytes.NewBufferString("👻"),
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/a/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/trampoline",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/trampoline/",
						Typeflag: tar.TypeSymlink,
						Linkname: ".",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/b/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/escape",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/escape",
						Typeflag: tar.TypeSymlink,
						Linkname: "trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/trampoline/../../../../../../../../../../../tmp",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/c/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/escape/poc.txt",
						Mode:     0777,
					},
				},
			},
			// No files should be extracted since the tar attempts to write files from outside the unpack
			// directory.
			want: map[string]contentAndMode{},
		},
		{
			name: "os.Root_detects_writing_files_outside_base_directory",
			cfg: unpack.DefaultUnpackerConfig().WithRequirer(require.NewFileRequirerPaths([]string{
				"/usr/share/doc/a/copyright",
				"/usr/share/doc/b/copyright",
				"/usr/share/doc/c/copyright",
			})),
			dir: t.TempDir(),
			tarEntries: []tarEntry{
				{
					Header: &tar.Header{
						Name: "/escape/poc.txt",
						Mode: 0777,
						Size: int64(len("👻")),
					},
					Data: bytes.NewBufferString("👻"),
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/a/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/trampoline",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/trampoline/",
						Typeflag: tar.TypeSymlink,
						Linkname: ".",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/b/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/escape",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/escape",
						Typeflag: tar.TypeSymlink,
						Linkname: "trampoline/trampoline/trampoline/trampoline/trampoline/../../../../tmp",
						Mode:     0777,
					},
				},
				{
					Header: &tar.Header{
						Name:     "/usr/share/doc/c/copyright",
						Typeflag: tar.TypeSymlink,
						Linkname: "/escape/poc.txt",
						Mode:     0777,
					},
				},
			},
			// No files should be extracted since the tar attempts to write files from outside the unpack
			// directory.
			want: map[string]contentAndMode{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tarDir := t.TempDir()
			tarPath := filepath.Join(tarDir, "tarball.tar")
			if err := createTarball(t, tarPath, tc.tarEntries); err != nil {
				t.Fatalf("Failed to create tarball: %v", err)
			}

			unpackDir := filepath.Join(tc.dir, "unpack")
			if err := os.MkdirAll(unpackDir, 0777); err != nil {
				t.Fatalf("Failed to create unpack dir: %v", err)
			}

			tmpFilesWant := filesInTmp(t, os.TempDir())

			u := mustNewUnpacker(t, tc.cfg)
			gotErr := u.UnpackSquashedFromTarball(unpackDir, tarPath)
			if !cmp.Equal(gotErr, tc.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Unpacker{%+v}.UnpackSquashedFromTarball(%q, %q) error: got %v, want %v\n", tc.cfg, unpackDir, tarPath, gotErr, tc.wantErr)
			}

			if tc.wantErr != nil {
				return
			}

			got := mustReadDir(t, tc.dir)
			if diff := cmp.Diff(tc.want, got, cmp.AllowUnexported(contentAndMode{})); diff != "" {
				t.Fatalf("Unpacker{%+v}.UnpackSquashed(%q, %q) returned unexpected diff (-want +got):\n%s", tc.cfg, unpackDir, tarPath, diff)
			}

			tmpFilesGot := filesInTmp(t, os.TempDir())

			// Check that no files were added to the tmp directory.
			less := func(a, b string) bool { return a < b }
			if diff := cmp.Diff(tmpFilesWant, tmpFilesGot, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

// mustNewUnpacker creates a new unpacker with the given config.
func mustNewUnpacker(t *testing.T, cfg *unpack.UnpackerConfig) *unpack.Unpacker {
	t.Helper()
	u, err := unpack.NewUnpacker(cfg)
	if err != nil {
		t.Fatalf("Failed to create unpacker: %v", err)
	}
	return u
}

// mustReadDir walks the directory dir returning a map of file paths to file content.
func mustReadDir(t *testing.T, dir string) map[string]contentAndMode {
	t.Helper()

	pathToContent := make(map[string]contentAndMode)
	err := filepath.Walk(dir, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("failed while walking directory given root (%s): %w", file, err)
		}

		// Skip directories
		if fi.IsDir() {
			return nil
		}

		// If file is a symlink, check if it points to a directory. If it does point to a directory,
		// skip it.
		//
		// TODO(b/366161799) Handle directories that are pointed to by symlinks. Skipping these
		// directories won't test their behavior, which is important as some images have symlinks that
		// point to directories.
		if (fi.Mode() & fs.ModeType) == fs.ModeSymlink {
			linkTarget, err := os.Readlink(file)
			if err != nil {
				return fmt.Errorf("failed to read destination of symlink %q: %w", file, err)
			}

			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(file), linkTarget)
			}

			linkFileInfo, err := os.Stat(linkTarget)

			if err != nil {
				return fmt.Errorf("failed to get file info of target link %q: %w", linkTarget, err)
			}

			// TODO(b/366161799) Change this to account for directories pointed to by symlinks.
			if linkFileInfo.IsDir() {
				return nil
			}
		}

		content, err := os.ReadFile(file)
		if err != nil {
			return fmt.Errorf("could not read file (%q): %w", file, err)
		}

		path, err := filepath.Rel(dir, file)
		if err != nil {
			return fmt.Errorf("filepath.Rel(%q, %q) failed: %w", dir, file, err)
		}
		pathToContent[path] = contentAndMode{
			content: string(content),
			mode:    fi.Mode(),
		}

		return nil
	})
	if err != nil {
		t.Fatalf("filepath.Walk(%q) failed: %v", dir, err)
	}

	return pathToContent
}

// mustNewSquashedImage returns a single layer
// This image may not contain parent directories because it is constructed from an intermediate tarball.
// This is useful for testing the parent directory creation logic of unpack.
func mustNewSquashedImage(t *testing.T, pathsToContent map[string]contentAndMode) v1.Image {
	t.Helper()

	// Squash layers into a single layer.
	files := make(map[string]contentAndMode)
	maps.Copy(files, pathsToContent)

	var buf bytes.Buffer
	w := tar.NewWriter(&buf)

	// Put the files in a single tarball to make a single layer and put that layer in an empty image to
	// make the minimal image that will work.
	for path, file := range files {
		hdr := &tar.Header{
			Name: path,
			Mode: int64(file.mode),
			Size: int64(len(file.content)),
		}
		if err := w.WriteHeader(hdr); err != nil {
			t.Fatalf("couldn't write header for %s: %v", path, err)
		}
		if _, err := w.Write([]byte(file.content)); err != nil {
			t.Fatalf("couldn't write %s: %v", path, err)
		}
	}
	_ = w.Close()
	layer, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewBuffer(buf.Bytes())), nil
	})
	if err != nil {
		t.Fatalf("unable to create layer: %v", err)
	}
	image, err := mutate.AppendLayers(empty.Image, layer)
	if err != nil {
		t.Fatalf("unable append layer to image: %v", err)
	}
	return image
}

// mustImageFromPath loads an image from a tarball at path.
func mustImageFromPath(t *testing.T, path string) v1.Image {
	t.Helper()
	image, err := tarball.ImageFromPath(path, nil)
	if err != nil {
		t.Fatalf("Failed to load image from path %q: %v", path, err)
	}
	return image
}

// filesInTmp returns the list of filenames in tmpDir.
func filesInTmp(t *testing.T, tmpDir string) []string {
	t.Helper()

	var filenames []string
	files, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("os.ReadDir('%q') error: %v", tmpDir, err)
	}

	for _, f := range files {
		if f.IsDir() {
			continue
		}

		filenames = append(filenames, f.Name())
	}
	return filenames
}

// tarEntry represents a single entry in a tarball. It contains the header and data for the entry.
// If the data is nil, the entry will be written without any content.
type tarEntry struct {
	Header *tar.Header
	Data   io.Reader
}

// createTarball creates a tarball at tarballPath with the given tar entries. If the tar entry's
// data is nil, the entry will be written without any content.
func createTarball(t *testing.T, tarballPath string, entries []tarEntry) error {
	t.Helper()

	file, err := os.Create(tarballPath)
	if err != nil {
		return fmt.Errorf("Failed to create tarball: %w", err)
	}
	defer file.Close()

	tarWriter := tar.NewWriter(file)
	defer tarWriter.Close()

	for _, entry := range entries {
		if err := tarWriter.WriteHeader(entry.Header); err != nil {
			return fmt.Errorf("writing header for %s: %w", entry.Header.Name, err)
		}
		if entry.Data != nil {
			if _, err := io.Copy(tarWriter, entry.Data); err != nil {
				return fmt.Errorf("writing content for %s: %w", entry.Header.Name, err)
			}
		}
	}
	return nil
}
