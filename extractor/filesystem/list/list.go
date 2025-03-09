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
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/java/pomxmlnet"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/bunlock"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/wordpress/plugins"
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
	"github.com/google/osv-scalibr/plugin"
	"golang.org/x/exp/maps"
)

// InitFn is the extractor initializer function.
type InitFn func() filesystem.Extractor

// InitMap is a map of extractor names to their initers.
type InitMap map[string][]InitFn

// LINT.IfChange
var (
	// Language extractors.

	// C++ extractors.
	Cpp = InitMap{conanlock.Name: {conanlock.New}}
	// Java extractors.
	Java = InitMap{
		gradlelockfile.Name:                {gradlelockfile.New},
		gradleverificationmetadataxml.Name: {gradleverificationmetadataxml.New},
		javaarchive.Name:                   {javaarchive.NewDefault},
		// pom.xml extraction for environments with and without network access.
		pomxml.Name:    {pomxml.New},
		pomxmlnet.Name: {pomxmlnet.NewDefault},
	}
	// Javascript extractors.
	Javascript = InitMap{
		packagejson.Name:     {packagejson.NewDefault},
		packagelockjson.Name: {packagelockjson.NewDefault},
		pnpmlock.Name:        {pnpmlock.New},
		yarnlock.Name:        {yarnlock.New},
		bunlock.Name:         {bunlock.New},
	}
	// Python extractors.
	Python = InitMap{
		wheelegg.Name:     {wheelegg.NewDefault},
		requirements.Name: {requirements.NewDefault},
		setup.Name:        {setup.NewDefault},
		pipfilelock.Name:  {pipfilelock.New},
		pdmlock.Name:      {pdmlock.New},
		poetrylock.Name:   {poetrylock.New},
		condameta.Name:    {condameta.NewDefault},
		uvlock.Name:       {uvlock.New},
	}
	// Go extractors.
	Go = InitMap{
		gobinary.Name: {gobinary.NewDefault},
		gomod.Name:    {gomod.New},
	}
	// Dart extractors.
	Dart = InitMap{pubspec.Name: {pubspec.New}}
	// Erlang extractors.
	Erlang = InitMap{mixlock.Name: {mixlock.New}}
	// Elixir extractors.
	Elixir = InitMap{elixir.Name: {elixir.NewDefault}}
	// Haskell extractors.
	Haskell = InitMap{
		stacklock.Name: {stacklock.NewDefault},
		cabal.Name:     {cabal.NewDefault},
	}
	// R extractors
	R = InitMap{renvlock.Name: {renvlock.New}}
	// Ruby extractors.
	Ruby = InitMap{
		gemspec.Name:     {gemspec.NewDefault},
		gemfilelock.Name: {gemfilelock.New},
	}
	// Rust extractors.
	Rust = InitMap{
		cargolock.Name:      {cargolock.New},
		cargoauditable.Name: {cargoauditable.NewDefault},
		cargotoml.Name:      {cargotoml.New},
	}
	// SBOM extractors.
	SBOM = InitMap{
		cdx.Name:  {cdx.New},
		spdx.Name: {spdx.New},
	}
	// Dotnet (.NET) extractors.
	Dotnet = InitMap{
		depsjson.Name:         {depsjson.NewDefault},
		packagesconfig.Name:   {packagesconfig.NewDefault},
		packageslockjson.Name: {packageslockjson.NewDefault},
	}
	// PHP extractors.
	PHP = InitMap{composerlock.Name: {composerlock.New}}
	// Swift extractors.

	Swift = InitMap{
		packageresolved.Name: {packageresolved.NewDefault},
		podfilelock.Name:     {podfilelock.NewDefault},
	}

	// Containers extractors.
	Containers = InitMap{containerd.Name: {containerd.NewDefault}} // Wordpress extractors.

	// Wordpress extractors.
	Wordpress = InitMap{plugins.Name: {plugins.NewDefault}}

	// OS extractors.
	OS = InitMap{
		dpkg.Name:     {dpkg.NewDefault},
		apk.Name:      {apk.NewDefault},
		rpm.Name:      {rpm.NewDefault},
		cos.Name:      {cos.NewDefault},
		snap.Name:     {snap.NewDefault},
		nix.Name:      {nix.New},
		module.Name:   {module.NewDefault},
		vmlinuz.Name:  {vmlinuz.NewDefault},
		pacman.Name:   {pacman.NewDefault},
		portage.Name:  {portage.NewDefault},
		flatpak.Name:  {flatpak.NewDefault},
		homebrew.Name: {homebrew.New},
		macapps.Name:  {macapps.NewDefault},
	}

	// Collections of extractors.

	// Default extractors that are recommended to be enabled.
	Default = concat(Java, Javascript, Python, Go, OS)
	// All extractors available from SCALIBR.
	All = concat(
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
		Wordpress,
	)

	extractorNames = concat(All, InitMap{
		// Languages.
		"cpp":        vals(Cpp),
		"java":       vals(Java),
		"javascript": vals(Javascript),
		"python":     vals(Python),
		"go":         vals(Go),
		"dart":       vals(Dart),
		"erlang":     vals(Erlang),
		"elixir":     vals(Elixir),
		"haskell":    vals(Haskell),
		"r":          vals(R),
		"ruby":       vals(Ruby),
		"dotnet":     vals(Dotnet),
		"php":        vals(PHP),
		"rust":       vals(Rust),
		"swift":      vals(Swift),

		"sbom":       vals(SBOM),
		"os":         vals(OS),
		"containers": vals(Containers),
		"wordpress":  vals(Wordpress),

		// Collections.
		"default": vals(Default),
		"all":     vals(All),
	})
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

func concat(InitMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range InitMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(InitMap InitMap) []InitFn {
	return slices.Concat(maps.Values(InitMap)...)
}

// FromCapabilities returns all extractors that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []filesystem.Extractor {
	all := []filesystem.Extractor{}
	for _, initers := range All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	return FilterByCapabilities(all, capabs)
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
		if initers, ok := extractorNames[n]; ok {
			for _, initer := range initers {
				e := initer()
				if _, ok := resultMap[e.Name()]; !ok {
					resultMap[e.Name()] = e
				}
			}
		} else {
			return nil, fmt.Errorf("unknown extractor %q", n)
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
	initers, ok := extractorNames[name]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %q", name)
	}
	if len(initers) != 1 {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	e := initers[0]()
	if e.Name() != name {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	return e, nil
}
