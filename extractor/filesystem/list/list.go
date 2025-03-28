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
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/containerd"
	"github.com/google/osv-scalibr/extractor/filesystem/language/cpp/conanlock"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dart/pubspec"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/depsjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/dotnetpe"
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
	chromeextensions "github.com/google/osv-scalibr/extractor/filesystem/misc/chrome/extensions"
	"github.com/google/osv-scalibr/extractor/filesystem/misc/vscodeextensions"
	wordpressplugins "github.com/google/osv-scalibr/extractor/filesystem/misc/wordpress/plugins"
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
)

// InitFn is the extractor initializer function.
type InitFn func() filesystem.Extractor

// InitMap is a map of extractor names to their initers.
type InitMap map[string][]InitFn

// LINT.IfChange
var (
	// Language extractors.

	// C++ source extractors.
	CppSource = InitMap{conanlock.Name: {conanlock.New}}
	// Java source extractors.
	JavaSource = InitMap{
		gradlelockfile.Name:                {gradlelockfile.New},
		gradleverificationmetadataxml.Name: {gradleverificationmetadataxml.New},
		// pom.xml extraction for environments with and without network access.
		pomxml.Name:    {pomxml.New},
		pomxmlnet.Name: {pomxmlnet.NewDefault},
	}
	// Java artifact extractors.
	JavaArtifact = InitMap{
		javaarchive.Name: {javaarchive.NewDefault},
	}
	// Javascript source extractors.
	JavascriptSource = InitMap{
		packagejson.Name:     {packagejson.NewDefault},
		packagelockjson.Name: {packagelockjson.NewDefault},
		pnpmlock.Name:        {pnpmlock.New},
		yarnlock.Name:        {yarnlock.New},
		bunlock.Name:         {bunlock.New},
	}
	// Javascript artifact extractors.
	JavascriptArtifact = InitMap{
		packagejson.Name: {packagejson.NewDefault},
	}
	// Python source extractors.
	PythonSource = InitMap{
		requirements.Name: {requirements.NewDefault},
		setup.Name:        {setup.NewDefault},
		pipfilelock.Name:  {pipfilelock.New},
		pdmlock.Name:      {pdmlock.New},
		poetrylock.Name:   {poetrylock.New},
		condameta.Name:    {condameta.NewDefault},
		uvlock.Name:       {uvlock.New},
	}
	// Python artifact extractors.
	PythonArtifact = InitMap{
		wheelegg.Name: {wheelegg.NewDefault},
	}
	// Go source extractors.
	GoSource = InitMap{
		gomod.Name: {gomod.New},
	}
	// Go artifact extractors.
	GoArtifact = InitMap{
		gobinary.Name: {gobinary.NewDefault},
	}
	// Dart source extractors.
	DartSource = InitMap{pubspec.Name: {pubspec.New}}
	// Erlang source extractors.
	ErlangSource = InitMap{mixlock.Name: {mixlock.New}}
	// Elixir source extractors.
	ElixirSource = InitMap{elixir.Name: {elixir.NewDefault}}
	// Haskell source extractors.
	HaskellSource = InitMap{
		stacklock.Name: {stacklock.NewDefault},
		cabal.Name:     {cabal.NewDefault},
	}
	// R source extractors
	RSource = InitMap{renvlock.Name: {renvlock.New}}
	// Ruby source extractors.
	RubySource = InitMap{
		gemspec.Name:     {gemspec.NewDefault},
		gemfilelock.Name: {gemfilelock.New},
	}
	// Rust source extractors.
	RustSource = InitMap{
		cargolock.Name:      {cargolock.New},
		cargoauditable.Name: {cargoauditable.NewDefault},
		cargotoml.Name:      {cargotoml.New},
	}
	// SBOM extractors.
	SBOM = InitMap{
		cdx.Name:  {cdx.New},
		spdx.Name: {spdx.New},
	}
	// Dotnet (.NET) source extractors.
	DotnetSource = InitMap{
		depsjson.Name:         {depsjson.NewDefault},
		packagesconfig.Name:   {packagesconfig.NewDefault},
		packageslockjson.Name: {packageslockjson.NewDefault},
	}
	// Dotnet (.NET) artifact extractors.
	DotnetArtifact = InitMap{
		dotnetpe.Name: {dotnetpe.NewDefault},
	}
	// PHP Source extractors.
	PHPSource = InitMap{composerlock.Name: {composerlock.New}}
	// Swift source extractors.
	SwiftSource = InitMap{
		packageresolved.Name: {packageresolved.NewDefault},
		podfilelock.Name:     {podfilelock.NewDefault},
	}

	// Container extractors.
	Containers = InitMap{containerd.Name: {containerd.NewDefault}} // Wordpress extractors.

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

	// Misc extractors.
	Misc = InitMap{
		vscodeextensions.Name: {vscodeextensions.New},
		wordpressplugins.Name: {wordpressplugins.NewDefault},
		chromeextensions.Name: {chromeextensions.New},
	}

	// Collections of extractors.

	// SourceCode extractors find packages in source code contexts (e.g. lockfiles).
	SourceCode = concat(
		CppSource,
		JavaSource,
		JavascriptSource,
		PythonSource,
		GoSource,
		DartSource,
		ErlangSource,
		ElixirSource,
		HaskellSource,
		PHPSource,
		RSource,
		RubySource,
		RustSource,
		DotnetSource,
		SwiftSource,
	)

	// Artifact extractors find packages on built systems (e.g. parsing
	// descriptors of installed packages).
	Artifact = concat(
		JavaArtifact,
		JavascriptArtifact,
		PythonArtifact,
		GoArtifact,
		DotnetArtifact,
		SBOM,
		OS,
		Misc,
		Containers,
	)

	// Default extractors that are recommended to be enabled.
	Default = concat(
		JavaSource, JavaArtifact,
		JavascriptSource, JavascriptArtifact,
		PythonSource, PythonArtifact,
		GoSource, GoArtifact,
		OS,
	)
	// All extractors available from SCALIBR.
	All = concat(
		SourceCode,
		Artifact,
	)

	extractorNames = concat(All, InitMap{
		// Languages.
		"cpp":        vals(CppSource),
		"java":       vals(concat(JavaSource, JavaArtifact)),
		"javascript": vals(concat(JavascriptSource, JavascriptArtifact)),
		"python":     vals(concat(PythonSource, PythonArtifact)),
		"go":         vals(concat(GoSource, GoArtifact)),
		"dart":       vals(DartSource),
		"erlang":     vals(ErlangSource),
		"elixir":     vals(ElixirSource),
		"haskell":    vals(HaskellSource),
		"r":          vals(RSource),
		"ruby":       vals(RubySource),
		"dotnet":     vals(concat(DotnetSource, DotnetArtifact)),
		"php":        vals(PHPSource),
		"rust":       vals(RustSource),
		"swift":      vals(SwiftSource),

		"sbom":       vals(SBOM),
		"os":         vals(OS),
		"containers": vals(Containers),
		"misc":       vals(Misc),

		// Collections.
		"artifact":   vals(Artifact),
		"sourcecode": vals(SourceCode),
		"default":    vals(Default),
		"all":        vals(All),
	})
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

func concat(initMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(initMap InitMap) []InitFn {
	return slices.Concat(slices.Collect(maps.Values(initMap))...)
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
