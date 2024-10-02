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

// Package list provides a public list of SCALIBR-internal extraction plugins.
package list

import (
	"fmt"
	"os"
	"slices"
	"strings"

	// OSV extractors.
	"github.com/google/osv-scanner/pkg/lockfile"

	// SCALIBR internal extractors.
	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	javaarchive "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/cos"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/flatpak"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

// LINT.IfChange
var (
	// Language extractors.

	// Java extractors.
	Java []filesystem.Extractor = []filesystem.Extractor{
		gradlelockfile.Extractor{},
		gradleverificationmetadataxml.Extractor{},
		javaarchive.New(javaarchive.DefaultConfig()),
		pomxml.Extractor{},
	}
	// Javascript extractors.
	Javascript []filesystem.Extractor = []filesystem.Extractor{packagejson.New(packagejson.DefaultConfig()), packagelockjson.New(packagelockjson.DefaultConfig()), &pnpmlock.Extractor{}}
	// Python extractors.
	Python []filesystem.Extractor = []filesystem.Extractor{
		wheelegg.New(wheelegg.DefaultConfig()),
		requirements.New(requirements.DefaultConfig()),
		pipfilelock.Extractor{},
		pdmlock.Extractor{},
		poetrylock.Extractor{},
	}
	// Go extractors.
	Go []filesystem.Extractor = []filesystem.Extractor{
		gobinary.New(gobinary.DefaultConfig()),
		&gomod.Extractor{},
	}
	// R extractors
	R []filesystem.Extractor = []filesystem.Extractor{renvlock.Extractor{}}
	// Ruby extractors.
	Ruby []filesystem.Extractor = []filesystem.Extractor{gemspec.New(gemspec.DefaultConfig())}
	// Rust extractors.
	Rust []filesystem.Extractor = []filesystem.Extractor{cargolock.Extractor{}}
	// SBOM extractors.
	SBOM []filesystem.Extractor = []filesystem.Extractor{&cdx.Extractor{}, &spdx.Extractor{}}
	// Dotnet (.NET) extractors.
	Dotnet []filesystem.Extractor = []filesystem.Extractor{packageslockjson.New(packageslockjson.DefaultConfig())}
	// PHP extractors.
	PHP []filesystem.Extractor = []filesystem.Extractor{&composerlock.Extractor{}}
	// Containers extractors.
	Containers []filesystem.Extractor = []filesystem.Extractor{containerd.New(containerd.DefaultConfig())}

	// OS extractors.
	OS []filesystem.Extractor = []filesystem.Extractor{
		dpkg.New(dpkg.DefaultConfig()),
		apk.New(apk.DefaultConfig()),
		rpm.New(rpm.DefaultConfig()),
		cos.New(cos.DefaultConfig()),
		snap.New(snap.DefaultConfig()),
		flatpak.New(flatpak.DefaultConfig()),
		homebrew.Extractor{}}

	// Collections of extractors.

	// Default extractors that are recommended to be enabled.
	Default []filesystem.Extractor = slices.Concat(Java, Javascript, Python, Go, OS)
	// All extractors available from SCALIBR. These don't include the untested extractors which can be enabled manually.
	All []filesystem.Extractor = slices.Concat(
		Java,
		Javascript,
		Python,
		Go,
		PHP,
		R,
		Ruby,
		Rust,
		Dotnet,
		SBOM,
		OS,
		// Containers,
	)

	// Untested extractors are OSV extractors without tests.
	// TODO(b/307735923): Add tests for these and move them into All.
	Untested []filesystem.Extractor = []filesystem.Extractor{
		osv.Wrapper{ExtractorName: "cpp/conan", ExtractorVersion: 0, PURLType: purl.TypeConan, Extractor: lockfile.ConanLockExtractor{}},
		osv.Wrapper{ExtractorName: "dart/pubspec", ExtractorVersion: 0, PURLType: purl.TypePub, Extractor: lockfile.PubspecLockExtractor{}},
		osv.Wrapper{ExtractorName: "javascript/yarn", ExtractorVersion: 0, PURLType: purl.TypeNPM, Extractor: lockfile.YarnLockExtractor{}},
		osv.Wrapper{ExtractorName: "ruby/gemfile", ExtractorVersion: 0, PURLType: purl.TypeGem, Extractor: lockfile.GemfileLockExtractor{}},
	}

	extractorNames = map[string][]filesystem.Extractor{
		// Languages.
		"java":       Java,
		"javascript": Javascript,
		"python":     Python,
		"go":         Go,
		"r":          R,
		"ruby":       Ruby,
		"dotnet":     Dotnet,
		"php":        PHP,
		"rust":       Rust,

		"sbom":       SBOM,
		"os":         OS,
		"containers": Containers,

		// Collections.
		"default":  Default,
		"all":      All,
		"untested": Untested,
	}
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

func init() {
	for _, e := range append(All, Untested...) {
		register(e)
	}
}

// register adds the individual extractors to the extractorNames map.
func register(d filesystem.Extractor) {
	if _, ok := extractorNames[strings.ToLower(d.Name())]; ok {
		log.Errorf("There are 2 extractors with the name: %q", d.Name())
		os.Exit(1)
	}
	extractorNames[strings.ToLower(d.Name())] = []filesystem.Extractor{d}
}

// FromCapabilities returns all extractors that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []filesystem.Extractor {
	return FilterByCapabilities(slices.Concat(All, Untested), capabs)
}

// FilterByCapabilities returns all extractors from the given list that can run
// under the specified capabilities (OS, direct filesystem access, network
// access, etc.) of the scanning environment.
func FilterByCapabilities(exs []filesystem.Extractor, capabs *plugin.Capabilities) []filesystem.Extractor {
	result := []filesystem.Extractor{}
	for _, ex := range exs {
		if err := plugin.ValidateRequirements(ex, capabs); err == nil {
			result = append(result, ex)
		}
	}
	return result
}

// ExtractorsFromNames returns a deduplicated list of extractors from a list of names.
func ExtractorsFromNames(names []string) ([]filesystem.Extractor, error) {
	resultMap := make(map[string]filesystem.Extractor)
	for _, n := range names {
		if es, ok := extractorNames[strings.ToLower(n)]; ok {
			for _, e := range es {
				if _, ok := resultMap[e.Name()]; !ok {
					resultMap[e.Name()] = e
				}
			}
		} else {
			return nil, fmt.Errorf("unknown extractor %s", n)
		}
	}
	result := make([]filesystem.Extractor, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}

// ExtractorFromName returns a single extractor based on its exact name.
func ExtractorFromName(name string) (filesystem.Extractor, error) {
	es, ok := extractorNames[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %s", name)
	}
	if len(es) != 1 || es[0].Name() != name {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	return es[0], nil
}
