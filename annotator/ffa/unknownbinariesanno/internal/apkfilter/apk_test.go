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

package apkfilter

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestShouldExclude(t *testing.T) {
	testCases := []struct {
		name       string
		path       string
		isExcluded bool
	}{
		{
			name:       "file in apk db dir",
			path:       "lib/apk/db/somefile",
			isExcluded: true,
		},
		{
			name:       "apk db dir itself",
			path:       "lib/apk/db",
			isExcluded: true,
		},
		{
			name:       "some other binary",
			path:       "usr/bin/some-other-file",
			isExcluded: false,
		},
		{
			name:       "path with db as prefix but not the full directory",
			path:       "lib/apk/d",
			isExcluded: false,
		},
		{
			name:       "empty path",
			path:       "",
			isExcluded: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := ApkFilter{}
			got := filter.ShouldExclude(context.Background(), nil, tc.path)
			if got != tc.isExcluded {
				t.Errorf("ShouldExclude(%q): got %v, want %v", tc.path, got, tc.isExcluded)
			}
		})
	}
}

func TestHashSetFilter(t *testing.T) {
	installed, err := os.ReadFile(filepath.Join("testdata", "installed"))
	if err != nil {
		t.Fatalf("failed to read testdata/installed: %v", err)
	}
	single, err := os.ReadFile(filepath.Join("testdata", "single"))
	if err != nil {
		t.Fatalf("failed to read testdata/single: %v", err)
	}
	invalid, err := os.ReadFile(filepath.Join("testdata", "invalid"))
	if err != nil {
		t.Fatalf("failed to read testdata/invalid: %v", err)
	}
	empty, err := os.ReadFile(filepath.Join("testdata", "empty"))
	if err != nil {
		t.Fatalf("failed to read testdata/empty: %v", err)
	}

	testCases := []struct {
		name               string
		files              map[string]string
		specialFSFn        func(t *testing.T, fl *fakelayer.FakeLayer) scalibrfs.FS
		unknownBinariesSet map[string]*extractor.Package
		want               map[string]*extractor.Package
		wantErr            bool
	}{
		{
			name: "basic case",
			files: map[string]string{
				"lib/apk/db/installed": `C:Q1...
P:package1
V:1.0
F:usr/bin
R:binary1
F:usr/lib
R:library1

C:Q2...
P:package2
V:1.0
F:bin
R:binary2
`,
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1":  {Name: "binary1"},
				"usr/lib/library1": {Name: "library1"},
				"bin/binary2":      {Name: "binary2"},
				"usr/bin/unknown1": {Name: "unknown1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/unknown1": {Name: "unknown1"},
			},
		},
		{
			name:  "apk db does not exist",
			files: map[string]string{},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			wantErr: true,
		},
		{
			name: "empty installed file",
			files: map[string]string{
				"lib/apk/db/installed": "",
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
		},
		{
			name: "with symlinks",
			files: map[string]string{
				"lib/apk/db/installed": `C:Q3...
P:package3
V:1.0
F:usr/bin
R:symlink1
F:path/to/another
R:symlink
`,
			},
			specialFSFn: func(t *testing.T, fl *fakelayer.FakeLayer) scalibrfs.FS {
				t.Helper()
				return fakefs.NewMockEvalSymlinksFS(fl, map[string]string{
					"/usr/bin/symlink1":        "/usr/bin/actual_binary",
					"/path/to/another/symlink": "/path/to/another/actual",
				})
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/symlink1":        {Name: "symlink1"},
				"usr/bin/actual_binary":   {Name: "actual_binary"},
				"path/to/another/symlink": {Name: "symlink"},
				"path/to/another/actual":  {Name: "another_actual"},
				"usr/bin/not_in_db":       {Name: "not_in_db"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/not_in_db": {Name: "not_in_db"},
			},
		},
		{
			name: "symlink in db but target not in set",
			files: map[string]string{
				"lib/apk/db/installed": `C:Q4...
P:package4
V:1.0
F:usr/bin
R:symlink2
`,
			},
			specialFSFn: func(t *testing.T, fl *fakelayer.FakeLayer) scalibrfs.FS {
				t.Helper()
				return fakefs.NewMockEvalSymlinksFS(fl, map[string]string{
					"/usr/bin/symlink2": "/usr/bin/actual_binary2",
				})
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/symlink2": {Name: "symlink2"},
				"usr/bin/unknown2": {Name: "unknown2"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/unknown2": {Name: "unknown2"},
			},
		},
		{
			name: "package with no files",
			files: map[string]string{
				"lib/apk/db/installed": `C:Q5...
P:package5
V:1.0
`,
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
		},
		{
			name: "installed file from testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(installed),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"etc/motd":           {Name: "motd"},
				"usr/bin/scanelf":    {Name: "scanelf"},
				"usr/bin/ssl_client": {Name: "ssl_client"},
				"lib/libz.so.1":      {Name: "libz.so.1"},
				"unknown/binary":     {Name: "unknown"},
			},
			want: map[string]*extractor.Package{
				"unknown/binary": {Name: "unknown"},
			},
		},
		{
			name: "single file from testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(single),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"etc/fstab":      {Name: "fstab"},
				"unknown/binary": {Name: "unknown"},
			},
			want: map[string]*extractor.Package{
				"unknown/binary": {Name: "unknown"},
			},
		},
		{
			name: "invalid file from testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(invalid),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			wantErr: true,
		},
		{
			name: "empty file from testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(empty),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fl, err := fakelayer.New(t.TempDir(), "", "", tc.files, false)
			if err != nil {
				t.Fatalf("fakelayer.New(): %v", err)
			}
			var fs scalibrfs.FS = fl
			if tc.specialFSFn != nil {
				fs = tc.specialFSFn(t, fl)
			}

			filter := ApkFilter{}
			err = filter.HashSetFilter(t.Context(), fs, tc.unknownBinariesSet)

			if (err != nil) != tc.wantErr {
				t.Fatalf("HashSetFilter() error = %v, wantErr %v", err, tc.wantErr)
			}
			if tc.wantErr {
				return
			}

			if diff := cmp.Diff(tc.want, tc.unknownBinariesSet); diff != "" {
				t.Errorf("HashSetFilter() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
