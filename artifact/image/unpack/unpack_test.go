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

package unpack_test

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"archive/tar"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	"github.com/google/go-containerregistry/pkg/v1/mutate"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
	"github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/osv-scalibr/artifact/image/require"
	"github.com/google/osv-scalibr/artifact/image/unpack"
)

type contentAndMode struct {
	content string
	mode    fs.FileMode
}

type digestAndContent struct {
	digest  string
	content map[string]contentAndMode
}

func TestNewUnpacker(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *unpack.UnpackerConfig
		want    *unpack.Unpacker
		wantErr error
	}{{
		name: "missing SymlinkResolution",
		cfg: &unpack.UnpackerConfig{
			SymlinkErrStrategy: unpack.SymlinkErrLog,
			Requirer:           &require.FileRequirerAll{},
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "missing SymlinkErrStrategy",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution: unpack.SymlinkRetain,
			Requirer:          &require.FileRequirerAll{},
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "missing Requirer",
		cfg: &unpack.UnpackerConfig{
			SymlinkResolution:  unpack.SymlinkRetain,
			SymlinkErrStrategy: unpack.SymlinkErrLog,
		},
		wantErr: cmpopts.AnyError,
	}, {
		name: "0 MaxFileBytes bytes",
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
		name: "all fields populated",
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
		name: "default config",
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
		dir:     mustMkdirTemp(t),
		image:   nil,
		wantErr: cmpopts.AnyError,
	}, {
		name:  "empty image",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: empty.Image,
		want:  map[string]contentAndMode{},
	}, {
		name:  "single layer image",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want: map[string]contentAndMode{
			"sample.txt":        contentAndMode{content: "sample text file\n", mode: fs.FileMode(0644)},
			"larger-sample.txt": contentAndMode{content: strings.Repeat("sample text file\n", 400), mode: fs.FileMode(0644)},
		},
	}, {
		name:  "large files are skipped",
		cfg:   unpack.DefaultUnpackerConfig().WithMaxFileBytes(1024),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want: map[string]contentAndMode{
			"sample.txt": contentAndMode{content: "sample text file\n", mode: fs.FileMode(0644)},
		},
	}, {
		name:  "image with restricted file permissions",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "permissions.tar")),
		want: map[string]contentAndMode{
			"sample.txt": contentAndMode{content: "sample text file\n", mode: fs.FileMode(0600)},
		},
	}, {
		name: "image with symlinks",
		cfg:  unpack.DefaultUnpackerConfig().WithMaxPass(1),
		dir: func() string {
			// Create an inner directory to unpack in and an outer directory to test if symlinks try pointing to it.
			// This test checks that symlinks that attempt to point outside the unpack directory are removed.
			dir := mustMkdirTemp(t)
			innerDir := filepath.Join(dir, "innerdir")
			err := os.Mkdir(innerDir, 0777)
			if err != nil {
				t.Fatalf("Failed to create temp dir: %v", err)
			}
			os.WriteFile(filepath.Join(dir, "secret.txt"), []byte("some secret\n"), 0644)
			return innerDir
		}(),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlink.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"):                {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/chain-symlink.txt"):                   {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/relative-dot-symlink.txt"):            {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/relative-symlink.txt"):                {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):                          {content: "sample text\n", mode: fs.FileMode(0644)},
			filepath.FromSlash("dir2/dir3/absolute-chain-symlink.txt"):     {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir2/dir3/absolute-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir2/dir3/relative-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
		},
	}, {
		name: "image with absolute path symlink but only the symlink is required",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(2).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/absolute-symlink.txt"),
			}),
		),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlink.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):           {content: "sample text\n", mode: fs.FileMode(0644)},
		},
	}, {
		name: "image with a chain of symlinks but only the first symlink is required",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(2).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/chain-symlink.txt"),
			}),
		),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlink.tar")),
		want: map[string]contentAndMode{
			filepath.FromSlash("dir1/absolute-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/chain-symlink.txt"):    {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			filepath.FromSlash("dir1/sample.txt"):           {content: "sample text\n", mode: fs.FileMode(0644)},
		},
	}, {
		name: "image with absolute path symlink, only the symlink is required, but there were not enough passes to resolve the symlink",
		cfg: unpack.DefaultUnpackerConfig().WithMaxPass(1).WithRequirer(
			require.NewFileRequirerPaths([]string{
				filepath.FromSlash("dir1/chain-symlink.txt"),
			}),
		),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlink.tar")),
		want:  map[string]contentAndMode{},
	}, {
		name: "image built from scratch (not through a tool like Docker)",
		cfg:  unpack.DefaultUnpackerConfig().WithMaxPass(1),
		dir:  mustMkdirTemp(t),
		image: mustNewSquashedImage(t, map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"):     {"some text", 0600},
			filepath.FromSlash("another/file.json"): {"some other text", 0600},
		}),
		want: map[string]contentAndMode{
			filepath.FromSlash("some/file.txt"):     {content: "some text", mode: fs.FileMode(0600)},
			filepath.FromSlash("another/file.json"): {content: "some other text", mode: fs.FileMode(0600)},
		},
	}, {
		name: "only some files are required",
		cfg:  unpack.DefaultUnpackerConfig().WithRequirer(require.NewFileRequirerPaths([]string{"some/file.txt"})),
		dir:  mustMkdirTemp(t),
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
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "dangling-symlinks.tar")),
		want:  map[string]contentAndMode{},
	}, {
		name:    "return error for unimplemented symlink ignore resolution strategy",
		cfg:     unpack.DefaultUnpackerConfig().WithSymlinkResolution(unpack.SymlinkIgnore),
		dir:     mustMkdirTemp(t),
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

func TestUnpackLayers(t *testing.T) {
	if runtime.GOOS != "linux" {
		// TODO(b/366163334): Make tests work on Mac and Windows.
		return
	}

	tests := []struct {
		name    string
		cfg     *unpack.UnpackerConfig
		dir     string
		image   v1.Image
		want    []digestAndContent
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
		dir:     mustMkdirTemp(t),
		image:   nil,
		wantErr: cmpopts.AnyError,
	}, {
		name:  "empty image",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: empty.Image,
		want:  []digestAndContent{{digest: "SQUASHED", content: map[string]contentAndMode{}}},
	}, {
		name:  "image with restricted file permissions",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "permissions.tar")),
		want: []digestAndContent{{
			digest: "SQUASHED",
			content: map[string]contentAndMode{
				"sample.txt": contentAndMode{content: "sample text file\n", mode: fs.FileMode(0600)},
			},
		}, {
			digest: "sha256:854d994f7942ac6711ff410417b58270562d322a251be74df7829c15ec31e369",
			content: map[string]contentAndMode{
				"sample.txt": contentAndMode{content: "sample text file\n", mode: fs.FileMode(0600)},
			},
		}},
	}, {
		name:  "basic",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "basic.tar")),
		want: []digestAndContent{{
			digest: "SQUASHED",
			content: map[string]contentAndMode{
				"sample.txt":        contentAndMode{content: "sample text file\n", mode: fs.FileMode(0644)},
				"larger-sample.txt": contentAndMode{content: strings.Repeat("sample text file\n", 400), mode: fs.FileMode(0644)},
			},
		}, {
			digest: "sha256:abfb541589db284238458b23f1607a184905159aa161c7325b725b4e2eaa1c2c",
			content: map[string]contentAndMode{
				"sample.txt": contentAndMode{content: "sample text file\n", mode: fs.FileMode(0644)},
			},
		}, {
			digest: "sha256:c2df653a81c5c96005972035fa076987c9e450e54a03de57aabdadc00e4939c4",
			content: map[string]contentAndMode{
				"larger-sample.txt": contentAndMode{content: strings.Repeat("sample text file\n", 400), mode: fs.FileMode(0644)},
			},
		}},
	}, {
		name:  "symlink",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "symlink.tar")),
		want: []digestAndContent{{
			digest: "SQUASHED",
			content: map[string]contentAndMode{
				filepath.FromSlash("dir1/absolute-symlink.txt"):                {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/chain-symlink.txt"):                   {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/relative-dot-symlink.txt"):            {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/relative-symlink.txt"):                {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/sample.txt"):                          {content: "sample text\n", mode: fs.FileMode(0644)},
				"dir2/dir3/absolute-chain-symlink.txt":                         {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir2/dir3/absolute-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir2/dir3/relative-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			},
		}, {
			digest: "sha256:5f09ece72b3eedea1a910b4b7450134b993c1c9196d46d5a258a21c16bc608f1",
			content: map[string]contentAndMode{
				filepath.FromSlash("dir1/absolute-symlink.txt"):     {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/chain-symlink.txt"):        {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/relative-dot-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/relative-symlink.txt"):     {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir1/sample.txt"):               {content: "sample text\n", mode: fs.FileMode(0644)},
			},
		}, {
			digest: "sha256:685207dee3dc9ffe6690c5eaa3a0e43c45f6493513e72b8ba6118931725c2436",
			content: map[string]contentAndMode{
				filepath.FromSlash("dir2/dir3/absolute-chain-symlink.txt"):     {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir2/dir3/absolute-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
				filepath.FromSlash("dir2/dir3/relative-subfolder-symlink.txt"): {content: "sample text\n", mode: fs.ModeSymlink | fs.FileMode(0777)},
			},
		}},
	}, {
		name:  "dangling symlinks are removed",
		cfg:   unpack.DefaultUnpackerConfig(),
		dir:   mustMkdirTemp(t),
		image: mustImageFromPath(t, filepath.Join("testdata", "dangling-symlinks.tar")),
		want: []digestAndContent{{
			digest:  "SQUASHED",
			content: map[string]contentAndMode{},
		}, {
			digest:  "sha256:f81cbf79992d9653b341a956ebf6b1e55897ab30b9a192a3b2dfca05d656b00c",
			content: map[string]contentAndMode{},
		}, {
			digest:  "sha256:4328c0fa137aec815fe39f3051df99a16e2e9ce622a7d22462e2fe04fbf720e8",
			content: map[string]contentAndMode{},
		}},
	},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {

			u := mustNewUnpacker(t, test.cfg)

			defer os.RemoveAll(test.dir)

			layerDigests, err := u.UnpackLayers(test.dir, test.image)
			if !cmp.Equal(err, test.wantErr, cmpopts.EquateErrors()) {
				t.Fatalf("Unpacker{%+v}.UnpackLayers(%q, %q) error: got %v, want %v\n", test.cfg, test.dir, test.image, err, test.wantErr)
			}

			var wantDigests []string
			if test.want != nil {
				wantDigests = []string{}
				for _, dc := range test.want {
					if dc.digest == "SQUASHED" {
						continue
					}
					wantDigests = append(wantDigests, dc.digest)
				}
			}

			if diff := cmp.Diff(wantDigests, layerDigests); diff != "" {
				t.Fatalf("Unpacker{%+v}.UnpackLayers(%q, %q) returned unexpected layer digest diff (-want +got):\n%s", test.cfg, test.dir, test.image, diff)
			}

			if test.wantErr != nil {
				return
			}

			opts := []cmp.Option{
				cmpopts.SortSlices(func(a, b digestAndContent) bool {
					return a.digest < b.digest
				}),
				cmp.AllowUnexported(contentAndMode{}),
				cmp.AllowUnexported(digestAndContent{}),
			}
			got := mustReadSubDirs(t, test.dir)
			if diff := cmp.Diff(test.want, got, opts...); diff != "" {
				t.Fatalf("Unpacker{%+v}.UnpackLayers(%q, %q) returned unexpected layer content diff (-want +got):\n%s", test.cfg, test.dir, test.image, diff)
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

// mustReadSubDirs reads all sub-directories of the given directory and returns a slice of digest
// (sub directory name) and content for each directory.
func mustReadSubDirs(t *testing.T, dir string) []digestAndContent {
	t.Helper()
	infos, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("os.ReadDir(%q) failed: %v", dir, err)
	}

	dc := []digestAndContent{}
	for _, info := range infos {
		if !info.IsDir() {
			t.Fatalf("os.ReadDir(%q) failed: %v", dir, err)
		}
		content := mustReadDir(t, filepath.Join(dir, info.Name()))
		dc = append(dc, digestAndContent{
			strings.Replace(info.Name(), "-", ":", -1),
			content,
		})
	}

	return dc
}

// mustNewSquashedImage returns a single layer
// This image may not contain parent directories because it is constructed from an intermediate tarball.
// This is useful for testing the parent directory creation logic of unpack.
func mustNewSquashedImage(t *testing.T, pathsToContent map[string]contentAndMode) v1.Image {

	// Squash layers into a single layer.
	files := make(map[string]contentAndMode)
	for path, contentAndMode := range pathsToContent {
		files[path] = contentAndMode
	}

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
	w.Close()
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

// mustMkdirTemp creates a temporary directory and returns its path.
func mustMkdirTemp(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	return dir
}
