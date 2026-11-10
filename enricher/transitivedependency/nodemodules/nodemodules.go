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

// Package nodemodules implements an enricher that reconstructs the dependency graph for
// NPM "installed" trees. It requires that the inventory provided by the relevant JavaScript
// extractors is complete, but it does not make network calls.
package nodemodules

import (
	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson/metadata"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/plugin/config"
)

const (
	// Name is the unique name of this enricher.
	Name = "transitivedependency/nodemodules"
)

// Enricher links packages in the inventory by solving direct dependency constraints.
type Enricher struct {
	internal.OfflineEnricher
}

// Name returns the name of the enricher.
func (e *Enricher) Name() string {
	return Name
}

// Version returns the version of the enricher.
func (Enricher) Version() int {
	return 0
}

// Requirements returns the capability requirements of the enricher.
func (Enricher) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// RequiredPlugins returns the names of the plugins required by the enricher.
func (Enricher) RequiredPlugins() []string {
	return []string{packagejson.Name}
}

// New creates a new Enricher.
func New(_ *config.PluginConfig) (enricher.Enricher, error) {
	return &Enricher{
		OfflineEnricher: internal.NewOfflineEnricher(&packageExtractor{}),
	}, nil
}

type packageExtractor struct{}

func (*packageExtractor) Extract(pkg *extractor.Package) *internal.DirectDependency {
	meta, ok := pkg.Metadata.(*metadata.JavascriptPackageJSONMetadata)
	if !ok {
		return nil
	}

	reqs := make([]resolve.RequirementVersion, 0, len(meta.Dependencies))
	for name, version := range meta.Dependencies {
		reqs = append(reqs, internal.NewRequirement(resolve.NPM, name, version))
	}
	return internal.NewDirectDependency(resolve.NPM, pkg, reqs)
}
