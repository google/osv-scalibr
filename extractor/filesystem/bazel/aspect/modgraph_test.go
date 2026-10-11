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
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseModGraph(t *testing.T) {
	graph := `{
  "key": "<root>", "name": "my_project", "version": "0.1.0", "root": true,
  "dependencies": [
    {"key": "grpc@1.74.1", "name": "grpc", "version": "1.74.1", "apparentName": "grpc",
     "dependencies": [
       {"key": "abseil-cpp@20250512.1", "name": "abseil-cpp", "version": "20250512.1", "dependencies": []}
     ]},
    {"key": "protobuf@31.1", "name": "protobuf", "version": "31.1", "dependencies": [],
     "indirectDependencies": [{"key": "zlib@1.3.1", "name": "zlib", "version": "1.3.1"}]},
    {"key": "abseil-cpp@20250512.1", "name": "abseil-cpp", "version": "20250512.1"},
    {"key": "local_mod@_", "name": "local_mod", "version": ""}
  ]
}`
	got, err := parseModGraph([]byte(graph))
	if err != nil {
		t.Fatalf("parseModGraph() error: %v", err)
	}
	want := moduleVersions{
		"grpc":       {"1.74.1"},
		"abseil-cpp": {"20250512.1"},
		"protobuf":   {"31.1"},
		"zlib":       {"1.3.1"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("parseModGraph() mismatch (-want +got):\n%s", diff)
	}

	if _, err := parseModGraph([]byte("not json")); err == nil {
		t.Error("parseModGraph(invalid) succeeded, want error")
	}
}

func TestModuleVersionsLookup(t *testing.T) {
	mv := moduleVersions{
		"grpc":     {"1.74.1"},
		"protobuf": {"29.0", "31.1"},
	}
	tests := []struct {
		canonical   string
		wantModule  string
		wantVersion string
		wantOK      bool
	}{
		// Bazel 8.
		{canonical: "grpc+", wantModule: "grpc", wantVersion: "1.74.1", wantOK: true},
		// Bazel 7.1+.
		{canonical: "grpc~", wantModule: "grpc", wantVersion: "1.74.1", wantOK: true},
		// Bazel 7.0.
		{canonical: "grpc~1.74.1", wantModule: "grpc", wantVersion: "1.74.1", wantOK: true},
		// multiple_version_override.
		{canonical: "protobuf+29.0", wantModule: "protobuf", wantVersion: "29.0", wantOK: true},
		{canonical: "protobuf+", wantModule: "protobuf", wantVersion: "", wantOK: true},
		// Module extension repos.
		{canonical: "gazelle++go_deps+com_github_foo_bar"},
		{canonical: "rules_python~~pip~pypi_311_numpy"},
		// Not in the graph.
		{canonical: "unknown+"},
		// Not a canonical module repo name.
		{canonical: "com_google_absl"},
		{canonical: ""},
	}
	for _, tt := range tests {
		t.Run(tt.canonical, func(t *testing.T) {
			module, version, ok := mv.lookup(tt.canonical)
			if module != tt.wantModule || version != tt.wantVersion || ok != tt.wantOK {
				t.Errorf("lookup(%q) = (%q, %q, %v), want (%q, %q, %v)", tt.canonical, module, version, ok, tt.wantModule, tt.wantVersion, tt.wantOK)
			}
		})
	}
}
