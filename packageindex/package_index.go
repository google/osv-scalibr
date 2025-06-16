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

// Package packageindex is a wrapper around the collected package, which
// provides methods for fast lookup of identified software.
package packageindex

import (
	"github.com/google/osv-scalibr/extractor"
)

// PackageIndex allows you to query the package result.
type PackageIndex struct {
	// Two-dimensional map: package type -> (package name -> Package).
	pkgMap map[string]map[string][]*extractor.Package
}

// New creates a PackageIndex based on the specified extraction results.
func New(pkgs []*extractor.Package) (*PackageIndex, error) {
	pkgMap := make(map[string]map[string][]*extractor.Package)
	for _, pkg := range pkgs {
		name := pkg.Name
		purlType := pkg.PURLType
		if p := pkg.PURL(); p != nil {
			name = p.Name
			purlType = p.Type
		}
		if _, ok := pkgMap[purlType]; !ok {
			pkgMap[purlType] = make(map[string][]*extractor.Package)
		}
		pkgMap[purlType][name] = append(pkgMap[purlType][name], pkg)
	}
	return &PackageIndex{pkgMap: pkgMap}, nil
}

// GetAll lists all detected software packages.
func (px *PackageIndex) GetAll() []*extractor.Package {
	result := []*extractor.Package{}
	for _, m := range px.pkgMap {
		for _, p := range m {
			result = append(result, p...)
		}
	}
	return result
}

// GetAllOfType lists all detected software package of a given purl
// package type (e.g. "deb" "golang" "pypi").
func (px *PackageIndex) GetAllOfType(pkgType string) []*extractor.Package {
	result := []*extractor.Package{}
	m, ok := px.pkgMap[pkgType]
	if !ok {
		return result
	}
	for _, p := range m {
		result = append(result, p...)
	}
	return result
}

// GetSpecific lists all versions of a software with the specified name+package type.
func (px *PackageIndex) GetSpecific(name string, pkgType string) []*extractor.Package {
	result := []*extractor.Package{}
	m, ok := px.pkgMap[pkgType]
	if !ok {
		return result
	}
	p, ok := m[name]
	if !ok {
		return result
	}
	return p
}
