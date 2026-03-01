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
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/common"
	"github.com/google/osv-scalibr/purl"
)

func TestExtractPackagesFromMSBuildXML(t *testing.T) {
	tests := []struct {
		name         string
		xml          string
		filePath     string
		wantPackages []*extractor.Package
		wantErr      bool
	}{
		{
			name: "single package reference",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="5.0.12" />
  </ItemGroup>
</Project>`,
			filePath: "project.csproj",
			wantPackages: []*extractor.Package{
				{
					Name:      "LiteDB",
					Version:   "5.0.12",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
			},
		},
		{
			name: "multiple package references",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="5.0.12" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>`,
			filePath: "project.csproj",
			wantPackages: []*extractor.Package{
				{
					Name:      "LiteDB",
					Version:   "5.0.12",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
				{
					Name:      "Newtonsoft.Json",
					Version:   "13.0.1",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
			},
		},
		{
			name: "multiple item groups",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="5.0.12" />
  </ItemGroup>
  <ItemGroup>
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
  </ItemGroup>
</Project>`,
			filePath: "project.csproj",
			wantPackages: []*extractor.Package{
				{
					Name:      "LiteDB",
					Version:   "5.0.12",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
				{
					Name:      "Newtonsoft.Json",
					Version:   "13.0.1",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
			},
		},
		{
			name:    "invalid xml",
			xml:     "not\nxml",
			wantErr: true,
		},
		{
			name: "empty include attribute",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="" Version="5.0.12" />
  </ItemGroup>
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "missing include attribute",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Version="5.0.12" />
  </ItemGroup>
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "empty version attribute",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="" />
  </ItemGroup>
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "missing version attribute",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" />
  </ItemGroup>
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "no package references",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
  </ItemGroup>
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "empty project",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
</Project>`,
			filePath:     "project.csproj",
			wantPackages: nil,
		},
		{
			name: "skips invalid entries but keeps valid ones",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="5.0.12" />
    <PackageReference Include="" Version="1.0.0" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.1" />
    <PackageReference Include="MissingVersion" />
  </ItemGroup>
</Project>`,
			filePath: "project.csproj",
			wantPackages: []*extractor.Package{
				{
					Name:      "LiteDB",
					Version:   "5.0.12",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
				{
					Name:      "Newtonsoft.Json",
					Version:   "13.0.1",
					PURLType:  purl.TypeNuget,
					Locations: []string{"project.csproj"},
				},
			},
		},
		{
			name: "file path is recorded in locations",
			xml: `<Project Sdk="Microsoft.NET.Sdk">
  <ItemGroup>
    <PackageReference Include="LiteDB" Version="5.0.12" />
  </ItemGroup>
</Project>`,
			filePath: "path/to/Directory.Packages.props",
			wantPackages: []*extractor.Package{
				{
					Name:      "LiteDB",
					Version:   "5.0.12",
					PURLType:  purl.TypeNuget,
					Locations: []string{"path/to/Directory.Packages.props"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.xml)
			got, err := common.ExtractPackagesFromMSBuildXML(r, tt.filePath)

			if tt.wantErr {
				if err == nil {
					t.Fatalf("ExtractPackagesFromMSBuildXML() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("ExtractPackagesFromMSBuildXML() unexpected error: %v", err)
			}

			less := func(a, b *extractor.Package) bool { return a.Name < b.Name }
			if diff := cmp.Diff(tt.wantPackages, got, cmpopts.SortSlices(less)); diff != "" {
				t.Errorf("ExtractPackagesFromMSBuildXML() diff (-want +got):\n%s", diff)
			}
		})
	}
}
