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

// Package list provides a public list of SCALIBR-internal extraction plugins.
package list

import (
	"fmt"
	"os"
	"slices"
	"strings"

	// OSV extractors.

	// SCALIBR internal extractors.
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"

	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packagesconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	elixir "github.com/google/osv-scalibr/extractor/filesystem/language/elixir/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/erlang/mixlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gomod"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/cabal"
	"github.com/google/osv-scalibr/extractor/filesystem/language/haskell/stacklock"
	javaarchive "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradlelockfile"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/gradleverificationmetadataxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/pnpmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/yarnlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/php/composerlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/condameta"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pdmlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/pipfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/poetrylock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/setup"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/uvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/r/renvlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargoauditable"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargolock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/rust/cargotoml"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/packageresolved"
	"github.com/google/osv-scalibr/extractor/filesystem/language/swift/podfilelock"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/cos"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/flatpak"
	"github.com/google/osv-scalibr/extractor/filesystem/os/homebrew"
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/module"
	"github.com/google/osv-scalibr/extractor/filesystem/os/kernel/vmlinuz"
	"github.com/google/osv-scalibr/extractor/filesystem/os/macapps"
	"github.com/google/osv-scalibr/extractor/filesystem/os/nix"
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

// LINT.IfChange
var (
	// Language extractors.

	// C++ extractors.
	Cpp []filesystem.Extractor = []filesystem.Extractor{conanlock.Extractor{}}
	// Java extractors.
	Java []filesystem.Extractor = []filesystem.Extractor{
		gradlelockfile.Extractor{},
		gradleverificationmetadataxml.Extractor{},
		javaarchive.New(javaarchive.DefaultConfig()),
		pomxml.Extractor{},
	}
	// Javascript extractors.
	Javascript []filesystem.Extractor = []filesystem.Extractor{
		packagejson.New(packagejson.DefaultConfig()),
		packagelockjson.New(packagelockjson.DefaultConfig()),
		&pnpmlock.Extractor{},
		&yarnlock.Extractor{},
		&bunlock.Extractor{},
	}
	// Python extractors.
	Python []filesystem.Extractor = []filesystem.Extractor{
		wheelegg.New(wheelegg.DefaultConfig()),
		requirements.New(requirements.DefaultConfig()),
		setup.New(setup.DefaultConfig()),
		pipfilelock.Extractor{},
		pdmlock.Extractor{},
		poetrylock.Extractor{},
		condameta.Extractor{},
		uvlock.Extractor{},
	}
	// Go extractors.
	Go []filesystem.Extractor = []filesystem.Extractor{
		gobinary.New(gobinary.DefaultConfig()),
		&gomod.Extractor{},
	}
	// Dart extractors.
	Dart []filesystem.Extractor = []filesystem.Extractor{pubspec.Extractor{}}
	// Erlang extractors.
	Erlang []filesystem.Extractor = []filesystem.Extractor{mixlock.Extractor{}}
	// Elixir extractors.
	Elixir []filesystem.Extractor = []filesystem.Extractor{elixir.Extractor{}}
	// Haskell extractors.
	Haskell []filesystem.Extractor = []filesystem.Extractor{stacklock.New(stacklock.DefaultConfig()), cabal.New(cabal.DefaultConfig())}
	// R extractors
	R []filesystem.Extractor = []filesystem.Extractor{renvlock.Extractor{}}
	// Ruby extractors.
	Ruby []filesystem.Extractor = []filesystem.Extractor{gemspec.New(gemspec.DefaultConfig()), &gemfilelock.Extractor{}}
	// Rust extractors.
	Rust []filesystem.Extractor = []filesystem.Extractor{
		cargolock.Extractor{},
		cargotoml.Extractor{},
		cargoauditable.New(cargoauditable.DefaultConfig()),
	}
	// SBOM extractors.
	SBOM []filesystem.Extractor = []filesystem.Extractor{&cdx.Extractor{}, &spdx.Extractor{}}
	// Dotnet (.NET) extractors.
	Dotnet []filesystem.Extractor = []filesystem.Extractor{
		depsjson.New(depsjson.DefaultConfig()),
		packagesconfig.New(packagesconfig.DefaultConfig()),
		packageslockjson.New(packageslockjson.DefaultConfig()),
	}
	// PHP extractors.
	PHP []filesystem.Extractor = []filesystem.Extractor{&composerlock.Extractor{}}
	// Swift extractors.

	Swift []filesystem.Extractor = []filesystem.Extractor{
		packageresolved.New(packageresolved.DefaultConfig()),
		podfilelock.New(podfilelock.DefaultConfig()),
	}

	// Containers extractors.
	Containers []filesystem.Extractor = []filesystem.Extractor{containerd.New(containerd.DefaultConfig())}

	// OS extractors.
	OS []filesystem.Extractor = []filesystem.Extractor{
		dpkg.New(dpkg.DefaultConfig()),
		apk.New(apk.DefaultConfig()),
		rpm.New(rpm.DefaultConfig()),
		cos.New(cos.DefaultConfig()),
		snap.New(snap.DefaultConfig()),
		nix.New(),
		module.New(module.DefaultConfig()),
		vmlinuz.New(vmlinuz.DefaultConfig()),
		pacman.New(pacman.DefaultConfig()),
		portage.New(portage.DefaultConfig()),
		flatpak.New(flatpak.DefaultConfig()),
		homebrew.Extractor{},
		macapps.New(macapps.DefaultConfig())}

	// Collections of extractors.

	// Default extractors that are recommended to be enabled.
	Default []filesystem.Extractor = slices.Concat(Java, Javascript, Python, Go, OS)
	// All extractors available from SCALIBR.
	All []filesystem.Extractor = slices.Concat(
		Cpp,
		Java,
		Javascript,
		Python,
		Go,
		Dart,
		Erlang,
		Elixir,
		Haskell,
		PHP,
		R,
		Ruby,
		Rust,
		Dotnet,
		SBOM,
		Swift,
		OS,
		Containers,
	)

	extractorNames = map[string][]filesystem.Extractor{
		// Languages.
		"cpp":        Cpp,
		"java":       Java,
		"javascript": Javascript,
		"python":     Python,
		"go":         Go,
		"dart":       Dart,
		"erlang":     Erlang,
		"elixir":     Elixir,
		"haskell":    Haskell,
		"r":          R,
		"ruby":       Ruby,
		"dotnet":     Dotnet,
		"php":        PHP,
		"rust":       Rust,
		"swift":      Swift,

		"sbom":       SBOM,
		"os":         OS,
		"containers": Containers,

		// Collections.
		"default": Default,
		"all":     All,
	}
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

//nolint:gochecknoinits
func init() {
	for _, e := range All {
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
	return FilterByCapabilities(All, capabs)
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
