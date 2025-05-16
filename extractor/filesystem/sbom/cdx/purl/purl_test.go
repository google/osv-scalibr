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
	cdxmeta "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/metadata"
	cdxpurl "github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx/purl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		desc     string
		metadata any
		want     *purl.PackageURL
	}{
		{
			desc:     "metadata_not_available",
			metadata: nil,
			want:     nil,
		},
		{
			desc: "metadata_available",
			metadata: &cdxmeta.Metadata{
				PURL: &purl.PackageURL{
					Type:      purl.TypePyPi,
					Name:      "name",
					Namespace: "namespace",
					Version:   "1.2.3",
				},
				CPEs: []string{},
			},
			want: &purl.PackageURL{
				Type:      purl.TypePyPi,
				Name:      "name",
				Namespace: "namespace",
				Version:   "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := cdxpurl.MakePackageURL(tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("cdxpurl.MakePackageURL(%v): unexpected PURL (-want +got):\n%s", tt.metadata, diff)
			}
		})
	}
}
