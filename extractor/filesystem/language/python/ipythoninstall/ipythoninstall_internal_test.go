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

package ipythoninstall

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/purl"
)

func TestPackagesFromCommandInstallMagics(t *testing.T) {
	tests := []struct {
		name string
		line string
		want []parsedPackage
	}{
		{
			name: "pip",
			line: "%pip install pandas==2.2.2",
			want: []parsedPackage{{name: "pandas", version: "2.2.2", purlType: purl.TypePyPi}},
		},
		{
			name: "conda",
			line: "%conda install scipy=1.14.1",
			want: []parsedPackage{{name: "scipy", version: "1.14.1", purlType: purl.TypeConda}},
		},
		{
			name: "mamba",
			line: "%mamba install scikit-learn=1.5.0",
			want: []parsedPackage{{name: "scikit-learn", version: "1.5.0", purlType: purl.TypeConda}},
		},
		{
			name: "micromamba",
			line: "%micromamba install polars=0.20.31",
			want: []parsedPackage{{name: "polars", version: "0.20.31", purlType: purl.TypeConda}},
		},
		{
			name: "uv",
			line: "%uv pip install anyio==4.6.2.post1",
			want: []parsedPackage{{name: "anyio", version: "4.6.2.post1", purlType: purl.TypePyPi}},
		},
		{
			name: "uv add",
			line: "%uv add fastapi==0.115.0",
			want: []parsedPackage{{name: "fastapi", version: "0.115.0", purlType: purl.TypePyPi}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, packagesFromCommand(tt.line), cmp.AllowUnexported(parsedPackage{})); diff != "" {
				t.Errorf("packagesFromCommand(%q) diff (-want +got):\n%s", tt.line, diff)
			}
		})
	}
}

func TestPackagesFromCommandAddOnlyAppliesToUV(t *testing.T) {
	line := "%pip add should-not-parse==1.0.0"
	if got := packagesFromCommand(line); len(got) != 0 {
		t.Errorf("packagesFromCommand(%q) = %+v, want nil", line, got)
	}
}

func TestPackagesFromCommandCondaInstallURLs(t *testing.T) {
	line := "%conda install https://conda.anaconda.org/conda-forge/linux-64/requests-2.32.3-pyhd8ed1ab_0.conda https://repo.anaconda.com/pkgs/main/linux-64/certifi-2025.4.26-py313h06a4308_0.tar.bz2 plainpkg=1.2.3"
	want := []parsedPackage{
		{name: "requests", version: "2.32.3", purlType: purl.TypeConda},
		{name: "certifi", version: "2025.4.26", purlType: purl.TypeConda},
		{name: "plainpkg", version: "1.2.3", purlType: purl.TypeConda},
	}

	if diff := cmp.Diff(want, packagesFromCommand(line), cmp.AllowUnexported(parsedPackage{})); diff != "" {
		t.Errorf("packagesFromCommand(%q) diff (-want +got):\n%s", line, diff)
	}
}

func TestPackagesFromCommandPipSkipsURLs(t *testing.T) {
	line := "%pip install https://example.test/packages/not-a-conda-install-1.0.0-py_0.conda requests==2.32.3"
	want := []parsedPackage{{name: "requests", version: "2.32.3", purlType: purl.TypePyPi}}

	if diff := cmp.Diff(want, packagesFromCommand(line), cmp.AllowUnexported(parsedPackage{})); diff != "" {
		t.Errorf("packagesFromCommand(%q) diff (-want +got):\n%s", line, diff)
	}
}
