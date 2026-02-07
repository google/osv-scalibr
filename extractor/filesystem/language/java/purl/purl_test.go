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

package purl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	archivemeta "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive/metadata"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/javalockfile"
	mavenpurl "github.com/google/osv-scalibr/extractor/filesystem/language/java/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		desc     string
		version  string
		metadata any
		want     *purl.PackageURL
	}{
		{
			desc:    "lowercase_name",
			version: "1.0.0",
			metadata: &javalockfile.Metadata{
				ArtifactID: "name",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeMaven,
				Name:    "name",
				Version: "1.0.0",
			},
		},
		{
			desc:    "mixed_case_name",
			version: "1.0.0",
			metadata: &javalockfile.Metadata{
				ArtifactID: "Name",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeMaven,
				Name:    "name",
				Version: "1.0.0",
			},
		},
		{
			desc:    "group_id",
			version: "1.0.0",
			metadata: &javalockfile.Metadata{
				GroupID:    "id",
				ArtifactID: "name",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeMaven,
				Namespace: "id",
				Name:      "name",
				Version:   "1.0.0",
			},
		},
		{
			desc:    "mixed_case_group_id",
			version: "1.0.0",
			metadata: &javalockfile.Metadata{
				GroupID:    "Id",
				ArtifactID: "name",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeMaven,
				Namespace: "id",
				Name:      "name",
				Version:   "1.0.0",
			},
		},
		{
			desc:    "archive_metadata",
			version: "1.0.0",
			metadata: &archivemeta.Metadata{
				GroupID:    "id",
				ArtifactID: "name",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeMaven,
				Namespace: "id",
				Name:      "name",
				Version:   "1.0.0",
			},
		},
		{
			desc:    "type_classifier",
			version: "1.0.0",
			metadata: &javalockfile.Metadata{
				ArtifactID: "name",
				Classifier: "classifier",
				Type:       "type",
			},
			want: &purl.PackageURL{
				Type:    purl.TypeMaven,
				Name:    "name",
				Version: "1.0.0",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					"classifier": "classifier",
					"type":       "type",
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := mavenpurl.MakePackageURL(tt.version, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("mavenpurl.MakePackageURL(%v, %v): unexpected diff (-want +got):\n%s", tt.version, tt.metadata, diff)
			}
		})
	}
}
