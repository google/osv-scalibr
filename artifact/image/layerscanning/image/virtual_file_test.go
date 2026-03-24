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
	"io"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

var (
	rootDirectory = &virtualFile{
		virtualPath: "/",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	rootFile = &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
	}
	nonRootDirectory = &virtualFile{
		virtualPath: "/dir1/dir2",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	nonRootFile = &virtualFile{
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
	}
)

// TODO: b/377551664 - Add tests for the Stat method for the virtualFile type.
func TestStat(t *testing.T) {
	baseTime := time.Now()
	regularVirtualFile := &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
		size:        1,
		modTime:     baseTime,
	}
	symlinkVirtualFile := &virtualFile{
		virtualPath: "/symlink-to-bar",
		targetPath:  "/bar",
		isWhiteout:  false,
		mode:        fs.ModeSymlink | filePermission,
		size:        1,
		modTime:     baseTime,
	}
	whiteoutVirtualFile := &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  true,
		mode:        filePermission,
	}

	type info struct {
		name    string
		size    int64
		mode    fs.FileMode
		modTime time.Time
	}

	tests := []struct {
		name     string
		node     *virtualFile
		wantInfo info
		wantErr  error
	}{
		{
			name: "regular_file",
			node: regularVirtualFile,
			wantInfo: info{
				name:    "bar",
				size:    1,
				mode:    filePermission,
				modTime: baseTime,
			},
		},
		{
			name: "symlink",
			node: symlinkVirtualFile,
			wantInfo: info{
				name:    "symlink-to-bar",
				size:    1,
				mode:    fs.ModeSymlink | filePermission,
				modTime: baseTime,
			},
		},
		{
			name:    "whiteout file",
			node:    whiteoutVirtualFile,
			wantErr: fs.ErrNotExist,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotVirtualFile, gotErr := tc.node.Stat()
			if tc.wantErr != nil {
				if diff := cmp.Diff(tc.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
					t.Errorf("Stat(%v) returned unexpected error (-want +got): %v", tc.node, diff)
				}
				return
			}

			gotInfo := info{
				name:    gotVirtualFile.Name(),
				size:    gotVirtualFile.Size(),
				mode:    gotVirtualFile.Mode(),
				modTime: gotVirtualFile.ModTime(),
			}
			if diff := cmp.Diff(tc.wantInfo, gotInfo, cmp.AllowUnexported(info{})); diff != "" {
				t.Errorf("Stat(%v) returned unexpected virtualFile (-want +got): %v", tc.node, diff)
			}
		})
	}
}

func TestRead(t *testing.T) {
	contentBlob := setupContentBlob(t, []string{"bar", "fuzz", "foo"})
	defer contentBlob.Close()
	defer os.Remove(contentBlob.Name())

	barSize := int64(len([]byte("bar")))
	fuzzSize := int64(len([]byte("fuzz")))
	fooSize := int64(len([]byte("foo")))

	barVirtualFile := &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
		size:        barSize,
		reader:      io.NewSectionReader(contentBlob, 0, barSize),
	}
	fuzzVirtualFile := &virtualFile{
		virtualPath: "/fuzz",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fuzzSize,
		reader:      io.NewSectionReader(contentBlob, barSize, fuzzSize),
	}
	nonRootFooVirtualFile := &virtualFile{
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fooSize,
		reader:      io.NewSectionReader(contentBlob, barSize+fuzzSize, fooSize),
	}
	whiteoutVirtualFile := &virtualFile{
		virtualPath: "/dir1/abc",
		isWhiteout:  true,
		mode:        filePermission,
	}
	dirVirtualFile := &virtualFile{
		virtualPath: "/dir1",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	tests := []struct {
		name     string
		vf       *virtualFile
		want     string
		wantSize int64
		wantErr  bool
	}{
		{
			name:     "unopened root file",
			vf:       barVirtualFile,
			want:     "bar",
			wantSize: 3,
		},
		{
			name:     "opened root file",
			vf:       fuzzVirtualFile,
			want:     "fuzz",
			wantSize: 4,
		},
		{
			name:     "non-root file",
			vf:       nonRootFooVirtualFile,
			want:     "foo",
			wantSize: 3,
		},
		{
			name:    "whiteout file",
			vf:      whiteoutVirtualFile,
			wantErr: true,
		},
		{
			name:    "dir file",
			vf:      dirVirtualFile,
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes := make([]byte, tc.wantSize)
			gotNumBytesRead, gotErr := tc.vf.Read(gotBytes)

			if gotErr != nil {
				if tc.wantErr {
					return
				}
				t.Fatalf("Read(%v) returned error: %v", tc.vf, gotErr)
			}

			gotContent := string(gotBytes[:gotNumBytesRead])
			if gotContent != tc.want {
				t.Errorf("Read(%v) = %v, want: %v", tc.vf, gotContent, tc.want)
			}

			// Close the file. The Close method is tested in a separate test.
			_ = tc.vf.Close()
		})
	}
}

func TestReadAt(t *testing.T) {
	bufferSize := 20
	contentBlob := setupContentBlob(t, []string{"bar", "fuzz", "foo"})
	defer contentBlob.Close()
	defer os.Remove(contentBlob.Name())

	barSize := int64(len([]byte("bar")))
	fuzzSize := int64(len([]byte("fuzz")))
	fooSize := int64(len([]byte("foo")))

	barVirtualFile := &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
		size:        barSize,
		reader:      io.NewSectionReader(contentBlob, 0, barSize),
	}
	fuzzVirtualFile := &virtualFile{
		virtualPath: "/fuzz",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fuzzSize,
		reader:      io.NewSectionReader(contentBlob, barSize, fuzzSize),
	}
	nonRootFooVirtualFile := &virtualFile{
		virtualPath: "/dir1/foo",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fooSize,
		reader:      io.NewSectionReader(contentBlob, barSize+fuzzSize, fooSize),
	}
	whiteoutVirtualFile := &virtualFile{
		virtualPath: "/dir1/abc",
		isWhiteout:  true,
		mode:        filePermission,
	}
	dirVirtualFile := &virtualFile{
		virtualPath: "/dir1",
		isWhiteout:  false,
		mode:        fs.ModeDir | dirPermission,
	}
	tests := []struct {
		name    string
		vf      *virtualFile
		offset  int64
		want    string
		wantErr error
	}{
		{
			name: "unopened_root_file",
			vf:   barVirtualFile,
			want: "bar",
			// All successful reads should return EOF
			wantErr: io.EOF,
		},
		{
			name:    "opened root file",
			vf:      fuzzVirtualFile,
			want:    "fuzz",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset",
			vf:      barVirtualFile,
			offset:  2,
			want:    "r",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset at the end of file",
			vf:      barVirtualFile,
			offset:  3,
			want:    "",
			wantErr: io.EOF,
		},
		{
			name:    "opened root file at offset beyond the end of file",
			vf:      barVirtualFile,
			offset:  4,
			want:    "",
			wantErr: io.EOF,
		},
		{
			name:    "non-root file",
			vf:      nonRootFooVirtualFile,
			want:    "foo",
			wantErr: io.EOF,
		},
		{
			name:    "non-root file at offset",
			vf:      nonRootFooVirtualFile,
			offset:  1,
			want:    "oo",
			wantErr: io.EOF,
		},
		{
			name:    "whiteout file",
			vf:      whiteoutVirtualFile,
			wantErr: os.ErrNotExist,
		},
		{
			name:    "dir file",
			vf:      dirVirtualFile,
			wantErr: errCannotReadVirutalDirectory,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotBytes := make([]byte, bufferSize)
			gotNumBytesRead, gotErr := tc.vf.ReadAt(gotBytes, tc.offset)
			// Close the file. The Close method is tested in a separate test.
			defer tc.vf.Close()

			if diff := cmp.Diff(tc.wantErr, gotErr, cmpopts.EquateErrors()); diff != "" {
				t.Errorf("ReadAt(%v) returned unexpected error (-want +got): %v", tc.vf, diff)
				return
			}

			gotContent := string(gotBytes[:gotNumBytesRead])
			if gotContent != tc.want {
				t.Errorf("ReadAt(%v) = %v, want: %v", tc.vf, gotContent, tc.want)
			}
		})
	}
}

// Test for the Seek method
func TestSeek(t *testing.T) {
	contentBlob := setupContentBlob(t, []string{"foo"})
	defer contentBlob.Close()
	defer os.Remove(contentBlob.Name())

	fooSize := int64(len([]byte("foo")))
	virtualFile := &virtualFile{
		virtualPath: "/foo",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fooSize,
		reader:      io.NewSectionReader(contentBlob, 0, fooSize),
	}

	// Test seeking to different positions
	tests := []struct {
		name   string
		offset int64
		whence int
		want   int64
	}{
		{
			name:   "seek to beginning",
			offset: 0,
			whence: io.SeekStart,
			want:   0,
		},
		{
			name:   "seek to current position",
			offset: 0,
			whence: io.SeekCurrent,
			want:   0,
		},
		{
			name:   "seek to end",
			offset: 0,
			whence: io.SeekEnd,
			want:   3,
		},
		{
			name:   "seek to 10 bytes from beginning",
			offset: 10,
			whence: io.SeekStart,
			want:   10,
		},
		{
			name:   "seek to 10 bytes from current position (at 0)",
			offset: 10,
			whence: io.SeekCurrent,
			want:   10,
		},
		{
			name:   "seek to 2 bytes from end",
			offset: -2,
			whence: io.SeekEnd,
			want:   1,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotPos, err := virtualFile.Seek(tc.offset, tc.whence)
			_ = virtualFile.Close()
			if err != nil {
				t.Fatalf("Seek failed: %v", err)
			}
			if gotPos != tc.want {
				t.Errorf("Seek returned incorrect position: got %d, want %d", gotPos, tc.want)
			}
		})
	}
}

func TestClose(t *testing.T) {
	contentBlob := setupContentBlob(t, []string{"foo"})
	defer contentBlob.Close()
	defer os.Remove(contentBlob.Name())

	fooSize := int64(len([]byte("foo")))

	vf := &virtualFile{
		virtualPath: "/foo",
		isWhiteout:  false,
		mode:        filePermission,
		size:        int64(len([]byte("foo"))),
		reader:      io.NewSectionReader(contentBlob, 0, fooSize),
	}

	tests := []struct {
		name string
		vf   *virtualFile
	}{
		{
			name: "close_root_file",
			vf:   vf,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotErr := tc.vf.Close()

			if gotErr != nil {
				t.Fatalf("Read(%v) returned error: %v", tc.vf, gotErr)
			}
		})
	}
}

func TestReadingAfterClose(t *testing.T) {
	const bufferSize = 20
	const readAndCloseEvents = 2

	contentBlob := setupContentBlob(t, []string{"foo", "bar"})
	defer contentBlob.Close()
	defer os.Remove(contentBlob.Name())

	fooSize := int64(len([]byte("foo")))
	barSize := int64(len([]byte("bar")))

	fooVirtualFile := &virtualFile{
		virtualPath: "/foo",
		isWhiteout:  false,
		mode:        filePermission,
		size:        fooSize,
		reader:      io.NewSectionReader(contentBlob, 0, fooSize),
	}
	barVirtualFile := &virtualFile{
		virtualPath: "/bar",
		isWhiteout:  false,
		mode:        filePermission,
		size:        barSize,
		reader:      io.NewSectionReader(contentBlob, fooSize, barSize),
	}

	tests := []struct {
		name    string
		vf      *virtualFile
		want    string
		wantErr bool
	}{
		{
			name: "unopened_root_file",
			vf:   fooVirtualFile,
			want: "foo",
		},
		{
			name: "opened_root_file",
			vf:   barVirtualFile,
			want: "bar",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			for range readAndCloseEvents {
				gotBytes := make([]byte, bufferSize)
				gotNumBytesRead, gotErr := tc.vf.Read(gotBytes)

				if gotErr != nil {
					if tc.wantErr {
						return
					}
					t.Fatalf("Read(%v) returned error: %v", tc.vf, gotErr)
				}

				gotContent := string(gotBytes[:gotNumBytesRead])
				if gotContent != tc.want {
					t.Errorf("Read(%v) = %v, want: %v", tc.vf, gotContent, tc.want)
				}

				err := tc.vf.Close()
				if err != nil {
					t.Fatalf("Close(%v) returned error: %v", tc.vf, err)
				}
			}
		})
	}
}

func TestName(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want string
	}{
		{
			name: "root_directory",
			node: rootDirectory,
			want: "",
		},
		{
			name: "root_file",
			node: rootFile,
			want: "bar",
		},
		{
			name: "non-root_file",
			node: nonRootFile,
			want: "foo",
		},
		{
			name: "non-root_directory",
			node: nonRootDirectory,
			want: "dir2",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.Name()
			if got != tc.want {
				t.Errorf("Name(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

func TestIsDir(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want bool
	}{
		{
			name: "root_directory",
			node: rootDirectory,
			want: true,
		},
		{
			name: "root_file",
			node: rootFile,
			want: false,
		},
		{
			name: "non-root_file",
			node: nonRootFile,
			want: false,
		},
		{
			name: "non-root_directory",
			node: nonRootDirectory,
			want: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.IsDir()
			if got != tc.want {
				t.Errorf("IsDir(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

func TestType(t *testing.T) {
	tests := []struct {
		name string
		node *virtualFile
		want fs.FileMode
	}{
		{
			name: "root_directory",
			node: rootDirectory,
			want: fs.ModeDir | dirPermission,
		},
		{
			name: "root_file",
			node: rootFile,
			want: filePermission,
		},
		{
			name: "non-root_file",
			node: nonRootFile,
			want: filePermission,
		},
		{
			name: "non-root_directory",
			node: nonRootDirectory,
			want: fs.ModeDir | dirPermission,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := tc.node.Type()
			if got != tc.want {
				t.Errorf("Type(%v) = %v, want: %v", tc.node, got, tc.want)
			}
		})
	}
}

// setupContentBlob creates a new file with a temporary content blob containing the given files.
func setupContentBlob(t *testing.T, files []string) *os.File {
	t.Helper()

	contentBlob, err := os.CreateTemp(t.TempDir(), "content-blob-*")
	if err != nil {
		t.Fatalf("Failed to create temporary file: %v", err)
	}
	for _, content := range files {
		if _, err := contentBlob.ReadFrom(strings.NewReader(content)); err != nil {
			t.Fatalf("Failed to write to temporary file: %v", err)
		}
	}
	return contentBlob
}
