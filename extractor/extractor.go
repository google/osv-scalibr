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
	"github.com/google/osv-scalibr/inventory/osvecosystem"
	"github.com/google/osv-scalibr/inventory/vex"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// Extractor is the common interface of inventory extraction plugins.
type Extractor interface {
	plugin.Plugin
}

// LINT.IfChange

// SourceCodeIdentifier lists additional identifiers for source code software packages (e.g. NPM).
type SourceCodeIdentifier struct {
	Repo   string
	Commit string
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
	// The PURL type of this package, e.g. "pypi". Used for purl generation.
	PURLType string
	// The names of the Plugins that found this software instance. Set by the core library.
	Plugins []string
	// Deprecated - use ExploitabilitySignals instead
	// TODO(b/400910349): Remove once integrators stop using this.
	AnnotationsDeprecated []Annotation
	// Signals to indicate that specific vulnerabilities are not applicable to this package.
	ExploitabilitySignals []*vex.PackageExploitabilitySignal
	// Details about the layer that the package was attributed to.
	LayerMetadata *LayerMetadata
	// The additional data found in the package.
	Metadata any
	// Licenses information of this package
	Licenses []string
}

// Annotation are additional information about the package.
// TODO(b/400910349): Remove once integrators switch to PackageExploitabilitySignal.
type Annotation int64

const (
	// Unknown is the default value for the annotation.
	Unknown Annotation = iota
	// Transitional packages just point to other packages without having actual code in them. This
	// happens for example when packages are renamed.
	Transitional
	// InsideOSPackage is set for packages that are found inside an OS package.
	InsideOSPackage
	// InsideCacheDir is set for packages that are found inside a cache directory.
	InsideCacheDir
)

// PURL returns the Package URL of this package.
func (p *Package) PURL() *purl.PackageURL {
	return toPURL(p)
}

// Ecosystem returns the Ecosystem of the package. For software packages this corresponds
// to an OSV ecosystem value, e.g. PyPI.
func (p *Package) Ecosystem() osvecosystem.Parsed {
	return toEcosystem(p)
}

// LINT.ThenChange(/binary/proto/scan_result.proto)
