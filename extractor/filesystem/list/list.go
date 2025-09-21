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
	"github.com/google/osv-scalibr/extractor/filesystem/containers/dockerbaseimage"
	"github.com/google/osv-scalibr/extractor/filesystem/containers/podman"
	"github.com/google/osv-scalibr/extractor/filesystem/language/asdf"
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
	"github.com/google/osv-scalibr/extractor/filesystem/language/lua/luarocks"
	"github.com/google/osv-scalibr/extractor/filesystem/language/nim/nimble"
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
	"github.com/google/osv-scalibr/extractor/filesystem/os/macports"
	"github.com/google/osv-scalibr/extractor/filesystem/os/nix"
	"github.com/google/osv-scalibr/extractor/filesystem/os/pacman"
	"github.com/google/osv-scalibr/extractor/filesystem/os/portage"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/os/snap"
	"github.com/google/osv-scalibr/extractor/filesystem/os/winget"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/cdx"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/convert"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	"github.com/google/osv-scalibr/veles/secrets/azuretoken"
	"github.com/google/osv-scalibr/veles/secrets/digitaloceanapikey"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
	"github.com/google/osv-scalibr/veles/secrets/gcpapikey"
	"github.com/google/osv-scalibr/veles/secrets/gcpexpressmode"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	"github.com/google/osv-scalibr/veles/secrets/github"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
	"github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
	"github.com/google/osv-scalibr/veles/secrets/hashicorpvault"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
	"github.com/google/osv-scalibr/veles/secrets/openai"
	"github.com/google/osv-scalibr/veles/secrets/perplexityapikey"
	"github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	"github.com/google/osv-scalibr/veles/secrets/privatekey"
	"github.com/google/osv-scalibr/veles/secrets/rubygemsapikey"
	"github.com/google/osv-scalibr/veles/secrets/tinkkeyset"
)

// InitFn is the extractor initializer function.
type InitFn func() filesystem.Extractor

// InitMap is a map of extractor names to their initers.
type InitMap map[string][]InitFn

// LINT.IfChange
var (
	// Language extractors.

	// CppSource extractors for C++.
	CppSource = InitMap{conanlock.Name: {conanlock.New}}
	// JavaSource extractors for Java.
	JavaSource = InitMap{
		gradlelockfile.Name:                {gradlelockfile.New},
		gradleverificationmetadataxml.Name: {gradleverificationmetadataxml.New},
		// pom.xml extraction for environments with and without network access.
		pomxml.Name:    {pomxml.New},
		pomxmlnet.Name: {pomxmlnet.NewDefault},
	}
	// JavaArtifact extractors for Java.
	JavaArtifact = InitMap{
		javaarchive.Name: {javaarchive.NewDefault},
	}
	// JavascriptSource extractors for Javascript.
	JavascriptSource = InitMap{
		packagejson.Name:     {packagejson.NewDefault},
		packagelockjson.Name: {packagelockjson.NewDefault},
		pnpmlock.Name:        {pnpmlock.New},
		yarnlock.Name:        {yarnlock.New},
		bunlock.Name:         {bunlock.New},
	}
	// JavascriptArtifact extractors for Javascript.
	JavascriptArtifact = InitMap{
		packagejson.Name: {packagejson.NewDefault},
	}
	// PythonSource extractors for Python.
	PythonSource = InitMap{
		// requirements extraction for environments with and without network access.
		requirements.Name: {requirements.NewDefault},
		setup.Name:        {setup.NewDefault},
		pipfilelock.Name:  {pipfilelock.New},
		pdmlock.Name:      {pdmlock.New},
		poetrylock.Name:   {poetrylock.New},
		condameta.Name:    {condameta.NewDefault},
		uvlock.Name:       {uvlock.New},
	}
	// PythonArtifact extractors for Python.
	PythonArtifact = InitMap{
		wheelegg.Name: {wheelegg.NewDefault},
	}
	// GoSource extractors for Go.
	GoSource = InitMap{
		gomod.Name: {gomod.New},
	}
	// GoArtifact extractors for Go.
	GoArtifact = InitMap{
		gobinary.Name: {gobinary.NewDefault},
	}
	// DartSource extractors for Dart.
	DartSource = InitMap{pubspec.Name: {pubspec.New}}
	// ErlangSource extractors for Erlang.
	ErlangSource = InitMap{mixlock.Name: {mixlock.New}}
	// NimSource extractors for Nim.
	NimSource = InitMap{nimble.Name: {nimble.New}}
	// LuaSource extractors for Lua.
	LuaSource = InitMap{luarocks.Name: {luarocks.New}}
	// ElixirSource extractors for Elixir.
	ElixirSource = InitMap{elixir.Name: {elixir.NewDefault}}
	// HaskellSource extractors for Haskell.
	HaskellSource = InitMap{
		stacklock.Name: {stacklock.NewDefault},
		cabal.Name:     {cabal.NewDefault},
	}
	// RSource extractors for R source extractors
	RSource = InitMap{renvlock.Name: {renvlock.New}}
	// RubySource extractors for Ruby.
	RubySource = InitMap{
		gemspec.Name:     {gemspec.NewDefault},
		gemfilelock.Name: {gemfilelock.New},
	}
	// RustSource extractors for Rust.
	RustSource = InitMap{
		cargolock.Name: {cargolock.New},
		cargotoml.Name: {cargotoml.New},
	}
	// RustArtifact extractors for Rust.
	RustArtifact = InitMap{
		cargoauditable.Name: {cargoauditable.NewDefault},
	}
	// SBOM extractors.
	SBOM = InitMap{
		cdx.Name:  {cdx.New},
		spdx.Name: {spdx.New},
	}
	// DotnetSource extractors for Dotnet (.NET).
	DotnetSource = InitMap{
		depsjson.Name:         {depsjson.NewDefault},
		packagesconfig.Name:   {packagesconfig.NewDefault},
		packageslockjson.Name: {packageslockjson.NewDefault},
	}
	// DotnetArtifact extractors for Dotnet (.NET).
	DotnetArtifact = InitMap{
		dotnetpe.Name: {dotnetpe.NewDefault},
	}
	// PHPSource extractors for PHP Source extractors.
	PHPSource = InitMap{composerlock.Name: {composerlock.New}}
	// SwiftSource extractors for Swift.
	SwiftSource = InitMap{
		packageresolved.Name: {packageresolved.NewDefault},
		podfilelock.Name:     {podfilelock.NewDefault},
	}

	// Containers extractors.
	Containers = InitMap{
		containerd.Name:      {containerd.NewDefault},
		podman.Name:          {podman.NewDefault},
		dockerbaseimage.Name: {dockerbaseimage.NewDefault},
	}

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
		macports.Name: {macports.New},
		winget.Name:   {winget.NewDefault},
	}

	// Secrets list extractors for credentials.
	Secrets = initMapFromVelesPlugins([]velesPlugin{
		{anthropicapikey.NewDetector(), "secrets/anthropicapikey", 0},
		{azuretoken.NewDetector(), "secrets/azuretoken", 0},
		{digitaloceanapikey.NewDetector(), "secrets/digitaloceanapikey", 0},
		{dockerhubpat.NewDetector(), "secrets/dockerhubpat", 0},
		{gcpapikey.NewDetector(), "secrets/gcpapikey", 0},
		{gcpexpressmode.NewDetector(), "secrets/gcpexpressmode", 0},
		{gcpsak.NewDetector(), "secrets/gcpsak", 0},
		{gitlabpat.NewDetector(), "secrets/gitlabpat", 0},
		{grokxaiapikey.NewAPIKeyDetector(), "secrets/grokxaiapikey", 0},
		{grokxaiapikey.NewManagementKeyDetector(), "secrets/grokxaimanagementkey", 0},
		{hashicorpvault.NewTokenDetector(), "secrets/hashicorpvaulttoken", 0},
		{hashicorpvault.NewAppRoleDetector(), "secrets/hashicorpvaultapprole", 0},
		{huggingfaceapikey.NewDetector(), "secrets/huggingfaceapikey", 0},
		{openai.NewDetector(), "secrets/openai", 0},
		{perplexityapikey.NewDetector(), "secrets/perplexityapikey", 0},
		{postmanapikey.NewAPIKeyDetector(), "secrets/postmanapikey", 0},
		{postmanapikey.NewCollectionTokenDetector(), "secrets/postmancollectiontoken", 0},
		{privatekey.NewDetector(), "secrets/privatekey", 0},
		{rubygemsapikey.NewDetector(), "secrets/rubygemsapikey", 0},
		{tinkkeyset.NewDetector(), "secrets/tinkkeyset", 0},
		{github.NewAppRefreshTokenDetector(), "secrets/githubapprefreshtoken", 0},
	})

	// Misc artifact extractors.
	Misc = InitMap{
		vscodeextensions.Name: {vscodeextensions.New},
		wordpressplugins.Name: {wordpressplugins.NewDefault},
		chromeextensions.Name: {chromeextensions.New},
	}

	// MiscSource extractors for miscellaneous purposes.
	MiscSource = InitMap{
		asdf.Name: {asdf.New},
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
		NimSource,
		LuaSource,
		Secrets,
		MiscSource,
	)

	// Artifact extractors find packages on built systems (e.g. parsing
	// descriptors of installed packages).
	Artifact = concat(
		JavaArtifact,
		JavascriptArtifact,
		PythonArtifact,
		GoArtifact,
		DotnetArtifact,
		RustArtifact,
		SBOM,
		OS,
		Misc,
		Containers,
		Secrets,
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
		"lua":        vals(LuaSource),
		"nim":        vals(NimSource),
		"elixir":     vals(ElixirSource),
		"haskell":    vals(HaskellSource),
		"r":          vals(RSource),
		"ruby":       vals(RubySource),
		"dotnet":     vals(concat(DotnetSource, DotnetArtifact)),
		"php":        vals(PHPSource),
		"rust":       vals(concat(RustSource, RustArtifact)),
		"swift":      vals(SwiftSource),

		"sbom":       vals(SBOM),
		"os":         vals(OS),
		"containers": vals(Containers),
		"secrets":    vals(Secrets),
		"misc":       vals(Misc),
		"miscsource": vals(MiscSource),

		// Collections.
		"artifact":           vals(Artifact),
		"sourcecode":         vals(SourceCode),
		"default":            vals(Default),
		"extractors/default": vals(Default),
		"all":                vals(All),
		"extractors/all":     vals(All),
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

// ExtractorsFromName returns a list of extractors from a name.
func ExtractorsFromName(name string) ([]filesystem.Extractor, error) {
	if initers, ok := extractorNames[name]; ok {
		result := []filesystem.Extractor{}
		for _, initer := range initers {
			result = append(result, initer())
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown extractor %q", name)
}

type velesPlugin struct {
	detector veles.Detector
	name     string
	version  int
}

func initMapFromVelesPlugins(plugins []velesPlugin) InitMap {
	result := InitMap{}
	for _, p := range plugins {
		result[p.name] = []InitFn{convert.FromVelesDetector(p.detector, p.name, p.version)}
	}
	return result
}
