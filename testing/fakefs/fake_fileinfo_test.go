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

package fakefs_test

import (
	"io/fs"
	"testing"
	"time"

	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestFakeFileInfo(t *testing.T) {
	tests := []struct {
		desc      string
		filename  string
		size      int64
		mode      fs.FileMode
		modTime   time.Time
		wantIsDir bool
	}{
		{
			desc:      "normal file",
			filename:  "test-file.txt",
			size:      1024,
			mode:      fs.ModePerm,
			modTime:   time.Unix(1_222_333_444, 0),
			wantIsDir: false,
		},
		{
			desc:      "directory file",
			filename:  "testdir",
			size:      0,
			mode:      fs.ModeDir,
			modTime:   time.Now(),
			wantIsDir: true,
		},
	}

	for _, test := range tests {
		t.Run(test.desc, func(t *testing.T) {
			var gotFileInfo fs.FileInfo = fakefs.FakeFileInfo{
				FileName:    test.filename,
				FileSize:    test.size,
				FileMode:    test.mode,
				FileModTime: test.modTime,
			}

			if gotFileInfo.Name() != test.filename {
				t.Errorf("FakeFileInfo.Name() = %q, want %q", gotFileInfo.Name(), test.filename)
			}
			if gotFileInfo.Size() != test.size {
				t.Errorf("FakeFileInfo.Size() = %d, want %d", gotFileInfo.Size(), test.size)
			}
			if gotFileInfo.Mode() != test.mode {
				t.Errorf("FakeFileInfo.Mode() = %v, want %v", gotFileInfo.Mode(), test.mode)
			}
			if !gotFileInfo.ModTime().Equal(test.modTime) {
				t.Errorf("FakeFileInfo.ModTime() = %v, want %v", gotFileInfo.ModTime(), test.modTime)
			}
			if gotFileInfo.IsDir() != test.wantIsDir {
				t.Errorf("FakeFileInfo.IsDir() = %v, want %v", gotFileInfo.IsDir(), test.wantIsDir)
			}
			if gotFileInfo.Sys() != nil {
				t.Errorf("FakeFileInfo.Sys() = %v, want nil", gotFileInfo.Sys())
			}
		})
	}
}
