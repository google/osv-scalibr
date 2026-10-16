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

package helper_test

import (
	"testing"

	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/helper"
)

func TestSplitNPMAlias(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantName    string
		wantVersion string
	}{
		{
			name:        "not an alias",
			input:       "1.2.3",
			wantName:    "",
			wantVersion: "1.2.3",
		},
		{
			name:        "empty",
			input:       "",
			wantName:    "",
			wantVersion: "",
		},
		{
			name:        "alias",
			input:       "npm:string-width@^4.2.0",
			wantName:    "string-width",
			wantVersion: "^4.2.0",
		},
		{
			name:        "scoped alias",
			input:       "npm:@babel/code-frame@7.0.0",
			wantName:    "@babel/code-frame",
			wantVersion: "7.0.0",
		},
		{
			name:        "alias with no version",
			input:       "npm:string-width",
			wantName:    "string-width",
			wantVersion: "",
		},
		{
			// The "@" here is the scope marker, not the separator before a version.
			name:        "scoped alias with no version",
			input:       "npm:@babel/code-frame",
			wantName:    "@babel/code-frame",
			wantVersion: "",
		},
		{
			name:        "alias with no package",
			input:       "npm:",
			wantName:    "",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotVersion := helper.SplitNPMAlias(tt.input)
			if gotName != tt.wantName || gotVersion != tt.wantVersion {
				t.Errorf("SplitNPMAlias(%q) = (%q, %q), want (%q, %q)",
					tt.input, gotName, gotVersion, tt.wantName, tt.wantVersion)
			}
		})
	}
}
