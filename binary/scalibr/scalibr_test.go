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

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestRun(t *testing.T) {
	tempDir := func(t *testing.T) string {
		t.Helper()
		return t.TempDir()
	}

	testCases := []struct {
		desc      string
		setupFunc func(t *testing.T) string
		args      []string
		want      int
	}{
		{
			desc:      "scan subcommand",
			setupFunc: tempDir,
			args:      []string{"scalibr", "scan", "--root", "{dir}", "--result", filepath.Join("{dir}", "result.textproto")},
			want:      0,
		},
		{
			desc:      "no subcommand",
			setupFunc: tempDir,
			args:      []string{"scalibr", "--root", "{dir}", "--result", filepath.Join("{dir}", "result.textproto")},
			want:      0,
		},
		{
			desc:      "scan subcommand with arg before flags",
			setupFunc: tempDir,
			args:      []string{"scalibr", "scan", "unknown", "--root", "{dir}", "--result", filepath.Join("{dir}", "result.textproto")},
			want:      1, // "Error parsing CLI args: either --result or --o needs to be set"
		},
		{
			desc:      "unknown subcommand",
			setupFunc: tempDir,
			// 'unknown' should be treated as the first argument to 'scan', which should fail as it's equivalent to the above test.
			args: []string{"scalibr", "unknown", "--root", "{dir}", "--result", filepath.Join("{dir}", "result.textproto")},
			want: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.desc, func(t *testing.T) {
			dir := tc.setupFunc(t)
			args := make([]string, len(tc.args))
			for i, arg := range tc.args {
				args[i] = strings.ReplaceAll(arg, "{dir}", dir)
			}
			if got := run(args); got != tc.want {
				t.Errorf("run(%v) returned unexpected exit code, got %d want %d", args, got, tc.want)
			}
		})
	}
}
