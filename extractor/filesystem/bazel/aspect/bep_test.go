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

package aspect

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestAspectOutputsFromBEP(t *testing.T) {
	tests := []struct {
		name      string
		bep       string
		want      []string
		wantError bool
	}{
		{
			name: "file_uris",
			bep: `{"id":{"namedSet":{"id":"0"}},"namedSetOfFiles":{"files":[{"name":"b.scalibr.json","uri":"file:///out/b.scalibr.json"},{"name":"a.scalibr.json","uri":"file:///out/a.scalibr.json"}]}}
{"id":{"namedSet":{"id":"1"}},"namedSetOfFiles":{"files":[{"uri":"file:///out/a.scalibr.json"},{"name":"lib.a","uri":"file:///out/lib.a"}]}}`,
			want: []string{filepath.FromSlash("/out/a.scalibr.json"), filepath.FromSlash("/out/b.scalibr.json")},
		},
		{
			name: "bytestream_uris_resolved_with_exec_root",
			bep: `{"id":{"namedSet":{"id":"0"}},"namedSetOfFiles":{"files":[{"name":"external/foo/x.scalibr.json","uri":"bytestream://cache/blobs/abc/1","pathPrefix":["bazel-out","k8-opt","bin"]}]}}
{"id":{"workspace":{}},"workspaceInfo":{"localExecRoot":"/exec/root"}}`,
			want: []string{filepath.FromSlash("/exec/root/bazel-out/k8-opt/bin/external/foo/x.scalibr.json")},
		},
		{
			name: "bytestream_uris_without_exec_root",
			bep:  `{"id":{"namedSet":{"id":"0"}},"namedSetOfFiles":{"files":[{"name":"x.scalibr.json","uri":"bytestream://cache/blobs/abc/1"}]}}`,
		},
		{
			name: "pretty_printed_events",
			bep: `{
  "namedSetOfFiles": {
    "files": [{"uri": "file:///out/a.scalibr.json"}]
  }
}`,
			want: []string{filepath.FromSlash("/out/a.scalibr.json")},
		},
		{
			name: "event_larger_than_bufio_scanner_limit",
			bep: `{"id":{"pattern":{}},"expanded":{"targets":["` + strings.Repeat("x", 5<<20) + `"]}}
{"namedSetOfFiles":{"files":[{"uri":"file:///out/a.scalibr.json"}]}}`,
			want: []string{filepath.FromSlash("/out/a.scalibr.json")},
		},
		{
			name: "truncated_stream_returns_partial_results",
			bep: `{"namedSetOfFiles":{"files":[{"uri":"file:///out/a.scalibr.json"}]}}
{"namedSetOfFiles":{"files":[{"uri":"file:///out/b.scal`,
			want:      []string{filepath.FromSlash("/out/a.scalibr.json")},
			wantError: true,
		},
		{
			name: "empty",
			bep:  "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := aspectOutputsFromBEP(strings.NewReader(tt.bep))
			if (err != nil) != tt.wantError {
				t.Errorf("aspectOutputsFromBEP() error = %v, want error: %v", err, tt.wantError)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("aspectOutputsFromBEP() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestLocalPath(t *testing.T) {
	tests := []struct {
		name     string
		file     bepFile
		execRoot string
		want     string
	}{
		{
			name: "file_uri",
			file: bepFile{URI: "file:///tmp/a%20b.scalibr.json"},
			want: filepath.FromSlash("/tmp/a b.scalibr.json"),
		},
		{
			name: "windows_file_uri",
			file: bepFile{URI: "file:///C:/out/a.scalibr.json"},
			want: filepath.FromSlash("C:/out/a.scalibr.json"),
		},
		{
			name:     "bytestream_uri",
			file:     bepFile{Name: "pkg/a.scalibr.json", URI: "bytestream://host/blobs/h/1", PathPrefix: []string{"bazel-out", "cfg", "bin"}},
			execRoot: "/root",
			want:     filepath.FromSlash("/root/bazel-out/cfg/bin/pkg/a.scalibr.json"),
		},
		{
			name: "bytestream_uri_without_exec_root",
			file: bepFile{Name: "pkg/a.scalibr.json", URI: "bytestream://host/blobs/h/1"},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := localPath(tt.file, tt.execRoot); got != tt.want {
				t.Errorf("localPath(%+v, %q) = %q, want %q", tt.file, tt.execRoot, got, tt.want)
			}
		})
	}
}
