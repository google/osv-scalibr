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

// Package common provides shared helpers for .NET extractors.
package common

import (
	"encoding/xml"
	"io"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
)

// PackageReference represents a single <PackageReference> element in an MSBuild XML file.
type PackageReference struct {
	Include string `xml:"Include,attr"`
	Version string `xml:"Version,attr"`
}

// ItemGroup represents an <ItemGroup> element containing package references.
type ItemGroup struct {
	PackageReferences []PackageReference `xml:"PackageReference"`
}

// Project represents the top-level <Project> element in an MSBuild XML file.
type Project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []ItemGroup `xml:"ItemGroup"`
}

// ExtractPackagesFromMSBuildXML decodes an MSBuild-style XML document from r and
// returns the NuGet packages declared as <PackageReference> elements.
// The filePath is recorded in each package's Locations field.
func ExtractPackagesFromMSBuildXML(r io.Reader, filePath string) ([]*extractor.Package, error) {
	var proj Project
	decoder := xml.NewDecoder(r)
	if err := decoder.Decode(&proj); err != nil {
		log.Errorf("Error parsing MSBuild XML file %s: %v", filePath, err)
		return nil, err
	}

	var result []*extractor.Package
	for _, ig := range proj.ItemGroups {
		for _, pkg := range ig.PackageReferences {
			if pkg.Include == "" || pkg.Version == "" {
				log.Warnf("Skipping package with missing name or version: %+v", pkg)
				continue
			}

			result = append(result, &extractor.Package{
				Name:      pkg.Include,
				Version:   pkg.Version,
				PURLType:  purl.TypeNuget,
				Locations: []string{filePath},
			})
		}
	}

	return result, nil
}
