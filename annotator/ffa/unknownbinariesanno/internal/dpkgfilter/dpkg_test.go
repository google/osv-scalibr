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

package dpkgfilter

import (
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
			name:       "file_in_dpkg_info_dir",
			path:       "var/lib/dpkg/info/somefile",
			isExcluded: true,
		},
		{
			name:       "policy-rc.d_file",
			path:       "usr/sbin/policy-rc.d",
			isExcluded: true,
		},
		{
			name:       "some_other_binary",
			path:       "usr/bin/some-other-file",
			isExcluded: false,
		},
		{
			name:       "dpkg_info_dir_itself",
			path:       "var/lib/dpkg/info",
			isExcluded: true,
		},
		{
			name:       "path_with_info_as_prefix_but_not_the_full_directory",
			path:       "var/lib/dpkg/inf",
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
			filter := DpkgFilter{}
			got := filter.ShouldExclude(t.Context(), nil, tc.path)
			if got != tc.isExcluded {
				t.Errorf("ShouldExclude(%q): got %v, want %v", tc.path, got, tc.isExcluded)
			}
		})
	}
}

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
			name: "basic_case",
			files: map[string]string{
				"var/lib/dpkg/info/package1.list":  "/usr/bin/binary1\n/usr/lib/library1\n",
				"var/lib/dpkg/info/package2.list":  "/bin/binary2\n",
				"var/lib/dpkg/info/not-a-list.txt": "/usr/bin/ignored",
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"usr/lib/library1": {Name: "library1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"bin/binary2": {Name: "binary2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"usr/bin/unknown1": {Name: "unknown1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"opt/google/binary": {Name: "google-binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"usr/lib/library1": {Name: "library1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"bin/binary2": {Name: "binary2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"usr/bin/unknown1": {Name: "unknown1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"opt/google/binary": {Name: "google-binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
		},
		{
			name:  "dpkg_info_dir_does_not_exist",
			files: map[string]string{},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
		},
		{
			name: "empty_list_file",
			files: map[string]string{
				"var/lib/dpkg/info/empty.list": "",
			},
			unknownBinariesSet: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/binary1": {Name: "binary1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
		},
		{
			name: "with_symlinks",
			files: map[string]string{
				"var/lib/dpkg/info/package3.list": "/usr/bin/symlink1\n/path/to/another/symlink\n",
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
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"usr/bin/actual_binary": {Name: "actual_binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"path/to/another/actual": {Name: "another_actual",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"usr/bin/not_in_list": {Name: "not_in_list",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/symlink1": {Name: "symlink1",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"usr/bin/actual_binary": {Name: "actual_binary",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"path/to/another/actual": {Name: "another_actual",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"usr/bin/not_in_list": {Name: "not_in_list",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
		},
		{
			name: "symlink_in_list_but_target_not_in_set",
			files: map[string]string{
				"var/lib/dpkg/info/package4.list": "/usr/bin/symlink2\n",
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
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
				"usr/bin/unknown2": {Name: "unknown2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
					}},
			},
			want: map[string]*extractor.Package{
				"usr/bin/symlink2": {Name: "symlink2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: true,
						},
					}},
				"usr/bin/unknown2": {Name: "unknown2",
					Metadata: &ubextr.UnknownBinaryMetadata{
						Attribution: ubextr.Attribution{
							BaseImage: false,
						},
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

			filter := DpkgFilter{}
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
