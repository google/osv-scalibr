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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	npmpurl "github.com/google/osv-scalibr/extractor/filesystem/language/javascript/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		desc     string
		name     string
		version  string
		metadata any
		want     *purl.PackageURL
	}{
		{
			desc:    "lowercase_name",
			name:    "name",
			version: "version",
			want: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "name",
				Version: "version",
			},
		},
		{
			desc:    "respects_mixed_case",
			name:    "Name",
			version: "version",
			want: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "Name",
				Version: "version",
			},
		},
		{
			desc:    "from_npm_repository_qualifier_set",
			name:    "Name",
			version: "version",
			metadata: &metadata.JavascriptPackageJSONMetadata{
				FromNPMRepository: true,
			},
			want: &purl.PackageURL{
				Type:    purl.TypeNPM,
				Name:    "Name",
				Version: "version",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"from-npm-repository": "true",
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := npmpurl.MakePackageURL(tt.name, tt.version, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("npmpurl.MakePackageURL(%v, %v): unexpected PURL (-want +got):\n%s", tt.name, tt.version, diff)
			}
		})
	}
}
