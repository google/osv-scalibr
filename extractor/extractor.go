// Copyright 2024 Google LLC
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

// Extractor is the common interface of inventory extraction plugins..
type Extractor interface {
	plugin.Plugin
	// ToPURL converts an inventory created by this extractor into a PURL.
	ToPURL(i *Inventory) (*purl.PackageURL, error)
	// ToCPEs converts an inventory created by this extractor into CPEs, if supported.
	ToCPEs(i *Inventory) ([]string, error)
	// Ecosystem returns the Ecosystem of the given inventory created by this extractor.
	// For software packages this corresponds to an OSV ecosystem value, e.g. PyPI.
	Ecosystem(i *Inventory) (string, error)
}

// LINT.IfChange

// SourceCodeIdentifier lists additional identifiers for source code software packages (e.g. NPM).
type SourceCodeIdentifier struct {
	Repo   string
	Commit string
}

// Inventory is an instance of a software package or library found by the extractor.
type Inventory struct {
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
	// The additional data found in the package.
	Metadata any
}

// Ecosystem returns the Ecosystem of the inventory. For software packages this corresponds
// to an OSV ecosystem value, e.g. PyPI.
func (i *Inventory) Ecosystem() (string, error) {
	return i.Extractor.Ecosystem(i)
}

// LINT.ThenChange(/binary/proto/scan_result.proto)
