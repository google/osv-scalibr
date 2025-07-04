package dpkgfilter

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
			name:       "file in dpkg info dir",
			path:       "var/lib/dpkg/info/somefile",
			isExcluded: true,
		},
		{
			name:       "policy-rc.d file",
			path:       "usr/sbin/policy-rc.d",
			isExcluded: true,
		},
		{
			name:       "some other binary",
			path:       "usr/bin/some-other-file",
			isExcluded: false,
		},
		{
			name:       "dpkg info dir itself",
			path:       "var/lib/dpkg/info",
			isExcluded: true,
		},
		{
			name:       "path with info as prefix but not the full directory",
			path:       "var/lib/dpkg/inf",
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
			filter := DpkgFilter{}
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
				"var/lib/dpkg/info/package1.list":  "/usr/bin/binary1\n/usr/lib/library1\n",
				"var/lib/dpkg/info/package2.list":  "/bin/binary2\n",
				"var/lib/dpkg/info/not-a-list.txt": "/usr/bin/ignored",
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
			name:  "dpkg info dir does not exist",
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
			name: "empty list file",
			files: map[string]string{
				"var/lib/dpkg/info/empty.list": "",
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
				"var/lib/dpkg/info/package3.list": "/usr/bin/symlink1\n/path/to/another/symlink\n",
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
				"usr/bin/not_in_list":    {Name: "not_in_list"},
			},
			want: map[string]*extractor.Package{
				"usr/bin/not_in_list": {Name: "not_in_list"},
			},
		},
		{
			name: "symlink in list but target not in set",
			files: map[string]string{
				"var/lib/dpkg/info/package4.list": "/usr/bin/symlink2\n",
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
