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

import "testing"

func TestNormalizeModuleName(t *testing.T) {
	tests := []struct {
		name string
		want string
	}{
		{"rules_go~1.20.0", "rules_go"},
		{"rules_go+1.20.0", "rules_go"},
		{"my_module~1.2.3~beta1", "beta1"},
		{"foo+0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b", "foo"}, // commit hash
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeModuleName(tt.name); got != tt.want {
				t.Errorf("normalizeModuleName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGetGoPkgNameFromURL(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/google/osv-scalibr/archive/v1.2.3.tar.gz", "github.com/google/osv-scalibr"},
		{"https://github.com/google/osv-scalibr.git", "github.com/google/osv-scalibr.git"}, // note: splitting at github.com/ gets google/osv-scalibr.git
		{"https://example.com/not/github", ""},
	}
	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			if got := getGoPkgNameFromURL(tt.url); got != tt.want {
				t.Errorf("getGoPkgNameFromURL() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseBzlmodName(t *testing.T) {
	tests := []struct {
		name     string
		wantName string
		wantPurl string
	}{
		{"npm__at_babel_core", "@babel/core", "npm"},
		{"npm__lodash", "lodash", "npm"},
		{"pip__requests", "requests", "pypi"},
		{"crates__serde-1.0.0", "serde", "cargo"},
		{"unknown__pkg", "unknown__pkg", "unknown"},
		{"noparts", "noparts", "unknown"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			purlType := "unknown"
			if got := parseBzlmodName(tt.name, &purlType); got != tt.wantName {
				t.Errorf("parseBzlmodName() = %v, want %v", got, tt.wantName)
			}
			if purlType != tt.wantPurl {
				t.Errorf("parseBzlmodName() purl = %v, want %v", purlType, tt.wantPurl)
			}
		})
	}
}
