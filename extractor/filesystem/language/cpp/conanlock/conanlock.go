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

// Package conanlock extracts conan.lock files.
package conanlock

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name is the unique name of this extractor.
	Name = "cpp/conanlock"
)

type conanReference struct {
	Name            string
	Version         string
	Username        string
	Channel         string
	RecipeRevision  string
	PackageID       string
	PackageRevision string
	TimeStamp       string
}

// conanGraphNode contains a subset of a graph entry that includes package information
type conanGraphNode struct {
	Pref string `json:"pref"`
	Ref  string `json:"ref"`
	Path string `json:"path"`
}

type conanGraphLock struct {
	Nodes map[string]conanGraphNode `json:"nodes"`
}

type conanLockFile struct {
	Version string `json:"version"`
	// conan v0.4- lockfiles use "graph_lock", "profile_host" and "profile_build"
	GraphLock conanGraphLock `json:"graph_lock,omitempty"`
	// conan v0.5+ lockfiles use "requires", "build_requires" and "python_requires"
	Requires       []string `json:"requires,omitempty"`
	BuildRequires  []string `json:"build_requires,omitempty"`
	PythonRequires []string `json:"python_requires,omitempty"`
}

func parseConanReference(ref string) conanReference {
	// very flexible format name/version[@username[/channel]][#rrev][:pkgid[#prev]][%timestamp]
	var reference conanReference

	parts := strings.SplitN(ref, "%", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.TimeStamp = parts[1]
	}

	parts = strings.SplitN(ref, ":", 2)
	if len(parts) == 2 {
		ref = parts[0]
		parts = strings.SplitN(parts[1], "#", 2)
		reference.PackageID = parts[0]
		if len(parts) == 2 {
			reference.PackageRevision = parts[1]
		}
	}

	parts = strings.SplitN(ref, "#", 2)
	if len(parts) == 2 {
		ref = parts[0]
		reference.RecipeRevision = parts[1]
	}

	parts = strings.SplitN(ref, "@", 2)
	if len(parts) == 2 {
		ref = parts[0]
		usernameChannel := parts[1]

		parts = strings.SplitN(usernameChannel, "/", 2)
		reference.Username = parts[0]
		if len(parts) == 2 {
			reference.Channel = parts[1]
		}
	}

	parts = strings.SplitN(ref, "/", 2)
	if len(parts) == 2 {
		reference.Name = parts[0]
		reference.Version = parts[1]
	} else {
		// consumer conanfile.txt or conanfile.py might not have a name
		reference.Name = ""
		reference.Version = ref
	}

	return reference
}

func parseConanV1Lock(lockfile conanLockFile) []*extractor.Package {
	var reference conanReference
	packages := make([]*extractor.Package, 0, len(lockfile.GraphLock.Nodes))

	for _, node := range lockfile.GraphLock.Nodes {
		if node.Path != "" {
			// a local "conanfile.txt", skip
			continue
		}

		if node.Pref != "" {
			// old format 0.3 (conan 1.27-) lockfiles use "pref" instead of "ref"
			reference = parseConanReference(node.Pref)
		} else if node.Ref != "" {
			reference = parseConanReference(node.Ref)
		} else {
			continue
		}
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}

		packages = append(packages, &extractor.Package{
			Name:     reference.Name,
			Version:  reference.Version,
			PURLType: purl.TypeConan,
			Metadata: osv.DepGroupMetadata{
				DepGroupVals: []string{},
			},
		})
	}

	return packages
}

func parseConanRequires(packages *[]*extractor.Package, requires []string, group string) {
	for _, ref := range requires {
		reference := parseConanReference(ref)
		// skip entries with no name, they are most likely consumer's conanfiles
		// and not dependencies to be searched in a database anyway
		if reference.Name == "" {
			continue
		}

		*packages = append(*packages, &extractor.Package{
			Name:     reference.Name,
			Version:  reference.Version,
			PURLType: purl.TypeConan,
			Metadata: osv.DepGroupMetadata{
				DepGroupVals: []string{group},
			},
		})
	}
}

func parseConanV2Lock(lockfile conanLockFile) []*extractor.Package {
	packages := make(
		[]*extractor.Package,
		0,
		uint64(len(lockfile.Requires))+uint64(len(lockfile.BuildRequires))+uint64(len(lockfile.PythonRequires)),
	)

	parseConanRequires(&packages, lockfile.Requires, "requires")
	parseConanRequires(&packages, lockfile.BuildRequires, "build-requires")
	parseConanRequires(&packages, lockfile.PythonRequires, "python-requires")

	return packages
}

func parseConanLock(lockfile conanLockFile) []*extractor.Package {
	if lockfile.GraphLock.Nodes != nil {
		return parseConanV1Lock(lockfile)
	}

	return parseConanV2Lock(lockfile)
}

// Extractor extracts Conan packages from conan.lock files.
type Extractor struct{}

// New returns a new instance of this Extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor
func (e Extractor) Name() string { return Name }

// Version of the extractor
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the specified file matches Conan lockfile patterns.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Base(api.Path()) == "conan.lock"
}

// Extract extracts packages from conan.lock files passed through the scan input.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var parsedLockfile *conanLockFile

	err := json.NewDecoder(input.Reader).Decode(&parsedLockfile)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("could not extract: %w", err)
	}

	pkgs := parseConanLock(*parsedLockfile)

	for i := range pkgs {
		pkgs[i].Locations = []string{input.Path}
	}

	return inventory.Inventory{Packages: pkgs}, nil
}

var _ filesystem.Extractor = Extractor{}
