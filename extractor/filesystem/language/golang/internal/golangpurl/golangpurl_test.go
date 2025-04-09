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

// Package golangpurl converts a package to a Golang type PackageURL.
package golangpurl_test

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/internal/golangpurl"
	"github.com/google/osv-scalibr/purl"
)

func TestMakePackageURL(t *testing.T) {
	tests := []struct {
		name string
		arg  extractor.Package
		want *purl.PackageURL
	}{
		{
			arg: extractor.Package{
				Name:    "github.com/google/osv-scalibr",
				Version: "1.2.3",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeGolang,
				Name:      "osv-scalibr",
				Namespace: "github.com/google",
				Version:   "1.2.3",
			},
		},
		{ // Lowercase the name and namespace
			arg: extractor.Package{
				Name:    "github.com/Microsoft/Go-Rustaudit",
				Version: "1.2.3",
			},
			want: &purl.PackageURL{
				Type:      purl.TypeGolang,
				Name:      "go-rustaudit",
				Namespace: "github.com/microsoft",
				Version:   "1.2.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := golangpurl.MakePackageURL(&tt.arg)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("MakePackageURL() returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}
