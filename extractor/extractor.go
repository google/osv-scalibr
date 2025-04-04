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

// Package extractor provides the common interface for standalone and filesystem extractors.
package extractor

import (
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor is the common interface of inventory extraction plugins.
type Extractor interface {
	plugin.Plugin
	// ToPURL converts a package created by this extractor into a PURL.
	ToPURL(p *Package) *purl.PackageURL
	// Ecosystem returns the Ecosystem of the given package created by this extractor.
	// For software packages this corresponds to an OSV ecosystem value, e.g. PyPI.
	Ecosystem(p *Package) string
}

// LINT.IfChange

// SourceCodeIdentifier lists additional identifiers for source code software packages (e.g. NPM).
type SourceCodeIdentifier struct {
	Repo   string
	Commit string
}

// LayerDetails stores details about the layer a package was found in.
type LayerDetails struct {
	Index       int
	DiffID      string
	Command     string
	InBaseImage bool
}

// Package is an instance of a software package or library found by the extractor.
// TODO(b/400910349): Currently package is also used to store non-package data
// like open ports. Move these into their own dedicated types.
// TODO(b/400910349): Move from extractor into a separate package such as inventory.
type Package struct {
	// A human-readable name representation of the package. Note that this field
	// should only be used for things like logging as different packages can have
	// multiple different types of names (e.g. .deb packages have a source name
	// and a binary name), in which case we arbitrarily pick one of them to use here.
	// In cases when the exact name type used is important (e.g. when matching
	// against vuln feeds) you should use the specific name field from the Metadata.
	Name string
	// The version of this package.
	Version string
	// Source code level package identifiers.
	SourceCode *SourceCodeIdentifier
	// Paths or source of files related to the package.
	Locations []string
	// The Extractor that found this software instance. Set by the core library.
	Extractor Extractor
	// Annotations are additional information about the package that is useful for matching.
	Annotations []Annotation
	// Details about the layer that the package was attributed to.
	LayerDetails *LayerDetails
	// The additional data found in the package.
	Metadata any
}

// Annotation are additional information about the package.
type Annotation int64

const (
	// Unknown is the default value for the annotation.
	Unknown Annotation = iota
	// Transitional packages just point to other packages without having actual code in them. This
	// happens for example when packages are renamed.
	Transitional
	// InsideOSPackage is set for packages that are found inside an OS package.
	// TODO(b/364536788): Annotation for language packages inside OS packages.
	InsideOSPackage
	// InsideCacheDir is set for packages that are found inside a cache directory.
	// TODO(b/364539671): Annotation for packages inside cache directories.
	InsideCacheDir
)

// Ecosystem returns the Ecosystem of the package. For software packages this corresponds
// to an OSV ecosystem value, e.g. PyPI.
func (p *Package) Ecosystem() string {
	return p.Extractor.Ecosystem(p)
}

// LINT.ThenChange(/binary/proto/scan_result.proto)
