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

package dpkg

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io"
	"io/fs"
	"runtime"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/klauspost/compress/zstd"
	"github.com/pierrec/lz4/v4"
	"golang.org/x/tools/txtar"
)

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error {
	return nil
}

// prepareMapFS builds an in-memory file system from a txtar string adding compression capabilities
func prepareMapFS(t *testing.T, txt string, emptyDir bool) fstest.MapFS {
	t.Helper()
	mfs := make(fstest.MapFS)

	if emptyDir {
		mfs[aptListDir] = &fstest.MapFile{Mode: fs.ModeDir}
	}

	for _, f := range txtar.Parse([]byte(txt)).Files {
		var (
			b bytes.Buffer
			w io.WriteCloser
		)
		// Automatically compress based on the file extension
		switch {
		case strings.HasSuffix(f.Name, ".gz"):
			w = gzip.NewWriter(&b)
		case strings.HasSuffix(f.Name, ".zst"):
			var err error
			w, err = zstd.NewWriter(&b)
			if err != nil {
				t.Fatal(err)
			}
		case strings.HasSuffix(f.Name, ".lz4"):
			w = lz4.NewWriter(&b)
		default:
			w = nopWriteCloser{Writer: &b}
		}
		if _, err := w.Write(f.Data); err != nil {
			t.Fatal(err)
		}
		w.Close()
		mfs[f.Name] = &fstest.MapFile{Data: b.Bytes(), Mode: 0644}
	}

	return mfs
}

func TestExtractAptCache(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Test skipped, OS unsupported: %v", runtime.GOOS)
	}

	tests := []struct {
		name     string
		txt      string
		emptyDir bool
		want     *aptCache
		wantErr  error
	}{
		{
			name:    "missing_apt_cache_folder_entirely",
			txt:     ``,
			wantErr: ErrMissingAptCache,
		},
		{
			name:     "empty apt cache directory",
			txt:      ``,
			emptyDir: true,
			wantErr:  ErrMissingAptCache,
		},
		{
			name: "valid_apt_cache_with_matching_and_non-matching_files",
			txt: `
-- var/lib/apt/lists/ports.ubuntu.com_ubuntu_dists_noble-updates_main_binary-arm64_Packages --
Package: curl
Version: 1.2.3
Architecture: amd64

Package: wget
Version: 4.5.6

-- storage.googleapis.com_dataproc-bigtop-repo_2%5f3%5fdeb12%5f20251203%5f064720-RC01_dists_dataproc_contrib_binary-amd64_Packages.lz4 --
Package: htop
Version: 2.0.0
`,
			want: &aptCache{
				value: map[string]struct{}{
					"curl": {},
					"wget": {},
				},
			},
		},
		{
			name: "multiple_OS",
			txt: `
-- var/lib/apt/lists/ports.ubuntu.com_ubuntu-ports_dists_noble-updates_main_binary-arm64_Packages.lz4 --
Package: curl
Version: 1.2.3
Architecture: amd64

-- var/lib/apt/lists/deb.debian.org_debian-security_dists_bookworm-security_main_binary-amd64_Packages.lz4 --
Package: htop
Version: 2.0.0

-- var/lib/apt/lists/deb.debian.org_debian_dists_bookworm_main_binary-amd64_Packages.lz4 --
Package: wget
Version: 4.5.6
`,
			want: &aptCache{
				value: map[string]struct{}{
					"curl": {},
					"wget": {},
					"htop": {},
				},
			},
		},
		{
			name: "handles_all_supported_compressed_file_formats",
			txt: `
-- var/lib/apt/lists/ports.ubuntu.com_ubuntu-ports_dists_noble-updates_main_binary-arm64_Packages.gz --
Package: test
-- var/lib/apt/lists/ports.ubuntu.com_ubuntu-ports_dists_noble-updates_main_binary-arm64_Packages.zst --
Package: test1
-- var/lib/apt/lists/ports.ubuntu.com_ubuntu-ports_dists_noble-updates_main_binary-arm64_Packages.lz4 --
Package: test2
`,
			want: &aptCache{
				value: map[string]struct{}{
					"test":  {},
					"test1": {},
					"test2": {},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mfs := prepareMapFS(t, tt.txt, tt.emptyDir)
			root := &scalibrfs.ScanRoot{FS: mfs}

			got, err := extractAptCache(root)

			if !errors.Is(err, tt.wantErr) {
				t.Errorf("extractAptCache() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			opts := []cmp.Option{
				cmp.AllowUnexported(aptCache{}),
				cmpopts.EquateEmpty(),
			}

			if diff := cmp.Diff(tt.want, got, opts...); diff != "" {
				t.Errorf("extractAptCache() (-want +got): %v", diff)
			}
		})
	}
}
