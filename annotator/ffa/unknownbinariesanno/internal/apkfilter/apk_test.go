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

package apkfilter

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/artifact/image/layerscanning/testing/fakelayer"
	"github.com/google/osv-scalibr/extractor"
	ubextr "github.com/google/osv-scalibr/extractor/filesystem/ffa/unknownbinariesextr"
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
			name:       "file_in_apk_db_dir",
			path:       "lib/apk/db/somefile",
			isExcluded: true,
		},
		{
			name:       "apk_db_dir_itself",
			path:       "lib/apk/db",
			isExcluded: true,
		},
		{
			name:       "some_other_binary",
			path:       "usr/bin/some-other-file",
			isExcluded: false,
		},
		{
			name:       "path_with_db_as_prefix_but_not_the_full_directory",
			path:       "lib/apk/d",
			isExcluded: false,
		},
		{
			name:       "empty_path",
			path:       "",
			isExcluded: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			filter := ApkFilter{}
			got := filter.ShouldExclude(t.Context(), nil, tc.path)
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
			name: "basic_case",
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
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/lib/library1": {Name: "library1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"bin/binary2": {Name: "binary2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/unknown1": {Name: "unknown1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					},
				},
				"usr/lib/library1": {Name: "library1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"bin/binary2": {Name: "binary2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/unknown1": {Name: "unknown1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name:  "apk_db_does_not_exist",
			files: map[string]string{},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			wantErr: true,
		},
		{
			name: "empty_installed_file",
			files: map[string]string{
				"lib/apk/db/installed": "",
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "with_symlinks",
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
				"usr/bin/symlink1": {Name: "symlink1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/actual_binary": {Name: "actual_binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"path/to/another/symlink": {Name: "symlink",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"path/to/another/actual": {Name: "another_actual",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/not_in_db": {Name: "not_in_db",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/symlink1": {Name: "symlink1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/actual_binary": {Name: "actual_binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"path/to/another/symlink": {Name: "symlink",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"path/to/another/actual": {Name: "another_actual",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/not_in_db": {Name: "not_in_db",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "symlink_in_db_but_target_not_in_set",
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
				"usr/bin/symlink2": {Name: "symlink2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/unknown2": {Name: "unknown2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/symlink2": {Name: "symlink2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/unknown2": {Name: "unknown2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "package_with_no_files",
			files: map[string]string{
				"lib/apk/db/installed": `C:Q5...
P:package5
V:1.0
`,
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "installed_file_from_testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(installed),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"etc/motd": {Name: "motd",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/scanelf": {Name: "scanelf",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"usr/bin/ssl_client": {Name: "ssl_client",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"lib/libz.so.1": {Name: "libz.so.1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"unknown/binary": {Name: "unknown",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"etc/motd": {Name: "motd",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/scanelf": {Name: "scanelf",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"usr/bin/ssl_client": {Name: "ssl_client",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"lib/libz.so.1": {Name: "libz.so.1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"unknown/binary": {Name: "unknown",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "single_file_from_testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(single),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"etc/fstab": {Name: "fstab",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
				"unknown/binary": {Name: "unknown",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"etc/fstab": {Name: "fstab",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							LocalFilesystem: true,
						},
					}},
				"unknown/binary": {Name: "unknown",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
		},
		{
			name: "invalid_file_from_testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(invalid),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			wantErr: true,
		},
		{
			name: "empty_file_from_testdata",
			files: map[string]string{
				"lib/apk/db/installed": string(empty),
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{},
					}},
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
