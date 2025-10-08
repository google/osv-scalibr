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

// Package purl provides functions to code and decode package url according to the spec: https://github.com/package-url/purl-spec
// This package is a convenience wrapper and abstraction layer around an existing open source implementation.
package purl

import (
	"fmt"
	"strings"

	"github.com/package-url/packageurl-go"
)

// These are the known purl types as defined in the spec. Some of these require
// special treatment during parsing.
// https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
const (
	// TypeAlpm is a pkg:alpm purl.
	TypeAlpm = "alpm"
	// TypeApk is a pkg:apk purl.
	TypeApk = "apk"
	// TypeBitbucket is a pkg:bitbucket purl.
	TypeBitbucket = "bitbucket"
	// TypeBrew is a pkg:brew purl.
	TypeBrew = "brew"
	// TypeCocoapods is a pkg:cocoapods purl.
	TypeCocoapods = "cocoapods"
	// TypeCargo is a pkg:cargo purl.
	TypeCargo = "cargo"
	// TypeComposer is a pkg:composer purl.
	TypeComposer = "composer"
	// TypeConan is a pkg:conan purl.
	TypeConan = "conan"
	// TypeConda is a pkg:conda purl.
	TypeConda = "conda"
	// TypeCOS is the pkg:cos purl
	TypeCOS = "cos"
	// TypeCran is a pkg:cran purl.
	TypeCran = "cran"
	// TypeDebian is a pkg:deb purl.
	TypeDebian = "deb"
	// TypeDocker is a pkg:docker purl.
	TypeDocker = "docker"
	// TypeK8s is a pkg:k8s purl.
	TypeK8s = "k8s"
	// TypeFlatpak is a pkg:flatpak purl.
	TypeFlatpak = "flatpak"
	// TypeGem is a pkg:gem purl.
	TypeGem = "gem"
	// TypeGeneric is a pkg:generic purl.
	TypeGeneric = "generic"
	// TypeGithub is a pkg:github purl.
	TypeGithub = "github"
	// TypeGolang is a pkg:golang purl.
	TypeGolang = "golang"
	// TypeHackage is a pkg:hackage purl.
	TypeHackage = "hackage"
	// TypeHaskell is a pkg:haskell purl.
	TypeHaskell = "haskell"
	// TypeMacApps is a pkg:macapps purl.
	TypeMacApps = "macapps"
	// TypeHex is a pkg:hex purl.
	TypeHex = "hex"
	// TypeMaven is a pkg:maven purl.
	TypeMaven = "maven"
	// TypeNix is a pkg:nix purl.
	TypeNix = "nix"
	// TypeNPM is a pkg:npm purl.
	TypeNPM = "npm"
	// TypePacman is a pkg:pacman purl.
	TypePacman = "pacman"
	// TypeNuget is a pkg:nuget purl.
	TypeNuget = "nuget"
	// TypeOCI is a pkg:oci purl
	TypeOCI = "oci"
	// TypeOpkg is a pkg:opkg purl.
	TypeOpkg = "opkg"
	// TypePub is a pkg:pub purl.
	TypePub = "pub"
	// TypePortage is a pkg:portage purl.
	TypePortage = "portage"
	// TypePyPi is a pkg:pypi purl.
	TypePyPi = "pypi"
	// TypeRPM is a pkg:rpm purl.
	TypeRPM = "rpm"
	// TypeSnap is a pkg:snap purl.
	TypeSnap = "snap"
	// TypeSwift is pkg:swift purl
	TypeSwift = "swift"
	// TypeGooget is pkg:googet purl
	TypeGooget = "googet"
	// TypeWordpress is pkg:wordpress purl
	TypeWordpress = "wordpress"
	// TypeAsdf is pkg:asdf purl
	TypeAsdf = "asdf"
	// TypeMacports is pkg:macports purl
	TypeMacports = "macports"
	// TypeWinget is pkg:winget purl
	TypeWinget = "winget"
	// TypeNim is pkg:nim purl
	TypeNim = "nim"
	// TypeLua is pkg:lua purl
	TypeLua = "lua"
)

// PackageURL is the struct representation of the parts that make a package url.
type PackageURL struct {
	Type       string
	Namespace  string
	Name       string
	Version    string
	Qualifiers Qualifiers
	Subpath    string
}

// Qualifier represents a single key=value qualifier in the package url.
type Qualifier packageurl.Qualifier

// Qualifiers is a slice of key=value pairs, with order preserved as it appears
// in the package URL.
type Qualifiers packageurl.Qualifiers

// QualifiersFromMap constructs a Qualifiers slice from a string map. To get a
// deterministic qualifier order (despite maps not providing any iteration order
// guarantees) the returned Qualifiers are sorted in increasing order of key.
func QualifiersFromMap(mm map[string]string) Qualifiers {
	for key, value := range mm {
		// Empty value strings are invalid qualifiers according to the purl spec
		// so we filter them out.
		if value == "" {
			delete(mm, key)
		}
	}
	return Qualifiers(packageurl.QualifiersFromMap(mm))
}

func (p PackageURL) String() string {
	purl := packageurl.PackageURL{
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: packageurl.Qualifiers(p.Qualifiers),
		Subpath:    p.Subpath,
	}
	return (&purl).String()
}

// FromString parses a valid package url string into a PackageURL structure.
func FromString(purl string) (PackageURL, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return PackageURL{}, fmt.Errorf("failed to decode PURL string %q: %w", purl, err)
	}
	if !validType(p.Type) {
		return PackageURL{}, fmt.Errorf("invalid PURL type %q", p.Type)
	}
	return PackageURL{
		Type:       p.Type,
		Namespace:  p.Namespace,
		Name:       p.Name,
		Version:    p.Version,
		Qualifiers: Qualifiers(p.Qualifiers),
		Subpath:    p.Subpath,
	}, nil
}

func validType(t string) bool {
	types := map[string]bool{
		TypeAlpm:      true,
		TypeApk:       true,
		TypeBitbucket: true,
		TypeBrew:      true,
		TypeCargo:     true,
		TypeCocoapods: true,
		TypeComposer:  true,
		TypeConan:     true,
		TypeConda:     true,
		TypeCOS:       true,
		TypeCran:      true,
		TypeDebian:    true,
		TypePacman:    true,
		TypeDocker:    true,
		TypeFlatpak:   true,
		TypeGem:       true,
		TypeGeneric:   true,
		TypeGithub:    true,
		TypeGolang:    true,
		TypeHackage:   true,
		TypeHaskell:   true,
		TypeNim:       true,
		TypeLua:       true,
		TypeHex:       true,
		TypeMacApps:   true,
		TypeMaven:     true,
		TypeNix:       true,
		TypeNPM:       true,
		TypeNuget:     true,
		TypeOCI:       true,
		TypeOpkg:      true,
		TypePub:       true,
		TypePortage:   true,
		TypePyPi:      true,
		TypeRPM:       true,
		TypeSwift:     true,
		TypeGooget:    true,
		TypeWordpress: true,
		TypeAsdf:      true,
		TypeMacports:  true,
		TypeWinget:    true,
	}

	// purl type is case-insensitive, canonical form is lower-case
	t = strings.ToLower(t)
	_, ok := types[t]
	return ok
}

// Qualifier names.
const (
	Distro              = "distro"
	Epoch               = "epoch"
	Arch                = "arch"
	Origin              = "origin"
	Source              = "source"
	SourceVersion       = "sourceversion"
	SourceRPM           = "sourcerpm"
	BuildNumber         = "buildnumber"
	PackageDependencies = "packagedependencies"
	Classifier          = "classifier" // Maven specific qualifier
	Type                = "type"       // Maven specific qualifier
)
