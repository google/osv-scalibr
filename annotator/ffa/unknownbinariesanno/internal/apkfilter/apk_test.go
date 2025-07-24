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
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/image"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/extractor"
	scalibrfs "github.com/google/osv-scalibr/fs"
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

type mockEvalSymlinksFS struct {
	scalibrfs.FS
	symlinks map[string]string
}

func (fs *mockEvalSymlinksFS) EvalSymlink(name string) (string, error) {
	if dest, ok := fs.symlinks[name]; ok {
		return dest, nil
	}
	return "", errors.New("not a symlink")
}

var _ image.EvalSymlinksFS = &mockEvalSymlinksFS{}

func TestHashSetFilter(t *testing.T) {
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
F:usr/bin/binary1
F:usr/lib/library1

C:Q2...
P:package2
V:1.0
F:bin/binary2
`,
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1":   {Name: "binary1"},
				"usr/lib/library1":  {Name: "library1"},
				"bin/binary2":       {Name: "binary2"},
				"usr/bin/unknown1":  {Name: "unknown1"},
				"opt/google/binary": {Name: "google-binary"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/unknown1":  {Name: "unknown1"},
				"opt/google/binary": {Name: "google-binary"},
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
F:usr/bin/symlink1
F:path/to/another/symlink
`,
			},
			specialFSFn: func(t *testing.T, fl *fakelayer.FakeLayer) scalibrfs.FS {
				t.Helper()
				return &mockEvalSymlinksFS{
					FS: fl,
					symlinks: map[string]string{
						"/usr/bin/symlink1":        "/usr/bin/actual_binary",
						"/path/to/another/symlink": "/path/to/another/actual",
					},
				}
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/symlink1":       {Name: "symlink1"},
				"usr/bin/actual_binary":  {Name: "actual_binary"},
				"path/to/another/actual": {Name: "another_actual"},
				"usr/bin/not_in_db":      {Name: "not_in_db"},
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
F:usr/bin/symlink2
`,
			},
			specialFSFn: func(t *testing.T, fl *fakelayer.FakeLayer) scalibrfs.FS {
				t.Helper()
				return &mockEvalSymlinksFS{
					FS: fl,
					symlinks: map[string]string{
						"/usr/bin/symlink2": "/usr/bin/actual_binary2",
					},
				}
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
