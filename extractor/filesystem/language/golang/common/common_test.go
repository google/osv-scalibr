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

package common_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	gocommon "github.com/google/osv-scalibr/extractor/filesystem/language/golang/common"
	golangmeta "github.com/google/osv-scalibr/extractor/filesystem/language/golang/metadata"
)

func TestApplyReplacement(t *testing.T) {
	tests := []struct {
		name           string
		replacePath    string
		replaceVersion string
		want           *extractor.Package
	}{{
		name:           "empty_replace_path_is_noop",
		replacePath:    "",
		replaceVersion: "",
		want:           &extractor.Package{Name: "example.com/orig", Version: "1.0.0"},
	}, {
		name:           "remote_replacement",
		replacePath:    "example.com/fork",
		replaceVersion: "v2.0.0",
		want:           &extractor.Package{Name: "example.com/fork", Version: "2.0.0"},
	}, {
		name:           "local_directory_replacement",
		replacePath:    "./staging/src/k8s.io/api",
		replaceVersion: "(devel)",
		want: &extractor.Package{
			Name:     "example.com/orig",
			Version:  "1.0.0",
			Metadata: &golangmeta.Metadata{LocalReplacePath: "./staging/src/k8s.io/api"},
		},
	}, {
		name:           "local_directory_replacement_empty_version",
		replacePath:    "../local/mod",
		replaceVersion: "",
		want: &extractor.Package{
			Name:     "example.com/orig",
			Version:  "1.0.0",
			Metadata: &golangmeta.Metadata{LocalReplacePath: "../local/mod"},
		},
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkg := &extractor.Package{Name: "example.com/orig", Version: "1.0.0"}
			gocommon.ApplyReplacement(pkg, tt.replacePath, tt.replaceVersion)
			if diff := cmp.Diff(tt.want, pkg); diff != "" {
				t.Errorf("ApplyReplacement() unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
