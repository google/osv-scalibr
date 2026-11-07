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

package mavenutil

import (
	"testing"

	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestIsPOMFile(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"pom.xml", true},
		{"POM.XML", true},
		{"pom-conventions.xml", true},
		{"pom-conventions.XML", true},
		{"pom-.xml", true},
		{"pom-abc.xml", true},
		{"parent-pom.xml", true},
		{"common-pom.xml", true},
		{"pom-conventions-pom.xml", true},
		{"not-pom.xml", true}, // Matches *-pom.xml
		{"my-app.pom", false},
		{"not-a-pom-file.xml", false},
		{"pom.xml.bak", false},
		{"apom.xml", false},
		{"pom", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := IsPOMFile(tt.path)
			if got != tt.want {
				t.Errorf("IsPOMFile(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestLocalModuleDirPOMs(t *testing.T) {
	txt := `
-- submodule/pom.xml --
<project/>
-- submodule/fh-pom.xml --
<project/>
-- submodule/README.md --
text
-- submodule/nested/pom.xml --
<project/>
-- pom.xml --
<project/>
`
	fsys, err := fakefs.PrepareFS(txt)
	if err != nil {
		t.Fatalf("failed to prepare fake fs: %v", err)
	}
	got := LocalModuleDirPOMs(fsys, nil)
	if len(got) != 0 {
		t.Errorf("LocalModuleDirPOMs(nil) = %v, want none", got)
	}
	got = LocalModuleDirPOMs(fsys, []string{"submodule/", "", ".", "missing", "../outside", "/abs"})
	want := map[string]bool{"submodule/pom.xml": true, "submodule/fh-pom.xml": true}
	if len(got) != len(want) {
		t.Fatalf("LocalModuleDirPOMs() = %v, want %v", got, want)
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("LocalModuleDirPOMs() returned unexpected %q", p)
		}
	}
}
