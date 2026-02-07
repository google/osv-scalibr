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
	"github.com/google/osv-scalibr/extractor/standalone/windows/common/metadata"
	winpurl "github.com/google/osv-scalibr/extractor/standalone/windows/common/purl"
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
			desc:    "no_os_version",
			name:    "name",
			version: "version",
			want: &purl.PackageURL{
				Type:      purl.TypeGeneric,
				Namespace: "microsoft",
				Name:      "name",
				Version:   "version",
			},
		},
		{
			desc:    "os_version",
			name:    "name",
			version: "version",
			metadata: &metadata.OSVersion{
				Product:     "product",
				FullVersion: "full-version",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeGeneric,
				Namespace: "microsoft",
				Name:      "name",
				Version:   "version",
				Qualifiers: purl.QualifiersFromMap(map[string]string{
					purl.BuildNumber: "full-version",
				}),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			got := winpurl.MakePackageURL(tt.name, tt.version, tt.metadata)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("winpurl.MakePackageURL(%v, %v, %v): unexpected PURL (-want +got):\n%s", tt.name, tt.version, tt.metadata, diff)
			}
		})
	}
}
