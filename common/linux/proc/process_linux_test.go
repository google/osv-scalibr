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

//go:build linux

package proc

import (
	"errors"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/google/go-cmp/cmp"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestReadProcessCmdline(t *testing.T) {
	tests := []struct {
		name    string
		pid     int64
		root    string
		fs      scalibrfs.FS
		want    []string
		wantErr error
	}{
		{
			name: "valid_cmdline_returned",
			pid:  1,
			root: "/",
			fs: fstest.MapFS{
				".":              {Mode: fs.ModeDir},
				"proc":           {Mode: fs.ModeDir},
				"proc/1":         {Mode: fs.ModeDir},
				"proc/1/cmdline": {Data: []byte("cat\x00-u\x00/proc/self/cmdline")},
			},
			want:    []string{"cat", "-u", "/proc/self/cmdline"},
			wantErr: nil,
		},
		{
			name: "invalid_pid_returns_error",
			pid:  1,
			root: "/",
			fs: fstest.MapFS{
				".":    {Mode: fs.ModeDir},
				"proc": {Mode: fs.ModeDir},
			},
			want:    []string{},
			wantErr: fs.ErrNotExist,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ReadProcessCmdline(t.Context(), tc.pid, tc.root, tc.fs)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("ReadProcessCmdline(%d, %q) returned an unexpected error: %v", tc.pid, tc.root, err)
			}

			if tc.wantErr != nil {
				return
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ReadProcessCmdline(%d, %q) returned an unexpected diff (-want +got): %v", tc.pid, tc.root, diff)
			}
		})
	}
}
