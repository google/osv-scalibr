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

package symlink_test

import (
	"runtime"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/artifact/image/symlink"
)

func TestTargetOutsideRoot(t *testing.T) {
	tests := []struct {
		name   string
		path   string
		target string
		want   bool
	}{{
		name:   "absolute target",
		path:   "/a/f.txt",
		target: "/a/f.txt",
		want:   false,
	}, {
		name:   "absolute path and relative target within root",
		path:   "/a/f.txt",
		target: "../t.txt",
		want:   false,
	}, {
		name:   "relative target within root",
		path:   "a/f.txt",
		target: "../t.txt",
		want:   false,
	}, {
		name:   "absolute path and relative target outside root",
		path:   "/a/f.txt",
		target: "../../t.txt",
		want:   true,
	}, {
		name:   "relative target outside root",
		path:   "a/f.txt",
		target: "../../t.txt",
		want:   true,
	}, {
		name:   "absolute_target_outside_root",
		path:   "a/f.txt",
		target: "/../t.txt",
		want:   true,
	}, {
		name:   "absolute target inside root",
		path:   "a/b/f.txt",
		target: "/a/../c/t.txt",
		want:   false,
	}}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// Use Windows-specific paths on Windows (e.g. /a/b/c -> C:\a\b\c)
			if runtime.GOOS == "windows" {
				tc.path = strings.ReplaceAll(tc.path, "/", "\\")
				if strings.HasPrefix(tc.path, "\\") {
					tc.path = "C:" + tc.path
				}

				tc.target = strings.ReplaceAll(tc.target, "/", "\\")
				if strings.HasPrefix(tc.target, "\\") {
					tc.target = "C:" + tc.target
				}
			}

			got := symlink.TargetOutsideRoot(tc.path, tc.target)
			if got != tc.want {
				t.Errorf("targetOutsideRoot(%v, %v) = %v, want %v", tc.path, tc.target, got, tc.want)
			}
		})
	}
}
