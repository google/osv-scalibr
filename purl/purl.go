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
	// COS is the pkg:cos purl
	TypeCOS = "cos"
	// TypeCran is a pkg:cran purl.
	TypeCran = "cran"
	// TypeDebian is a pkg:deb purl.
	TypeDebian = "deb"
	// TypeDocker is a pkg:docker purl.
	TypeDocker = "docker"
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
	// TypeHex is a pkg:hex purl.
	TypeHex = "hex"
	// TypeMaven is a pkg:maven purl.
	TypeMaven = "maven"
	// TypeNPM is a pkg:npm purl.
	TypeNPM = "npm"
	// TypeNuget is a pkg:nuget purl.
	TypeNuget = "nuget"
	// TypeOCI is a pkg:oci purl
	TypeOCI = "oci"
	// TypePub is a pkg:pub purl.
	TypePub = "pub"
	// TypePyPi is a pkg:pypi purl.
	TypePyPi = "pypi"
	// TypeRPM is a pkg:rpm purl.
	TypeRPM = "rpm"
	// TypeSwift is pkg:swift purl
	TypeSwift = "swift"
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
		TypeCargo:     true,
		TypeCocoapods: true,
		TypeComposer:  true,
		TypeConan:     true,
		TypeConda:     true,
		TypeCOS:       true,
		TypeCran:      true,
		TypeDebian:    true,
		TypeDocker:    true,
		TypeGem:       true,
		TypeGeneric:   true,
		TypeGithub:    true,
		TypeGolang:    true,
		TypeHackage:   true,
		TypeHex:       true,
		TypeMaven:     true,
		TypeNPM:       true,
		TypeNuget:     true,
		TypeOCI:       true,
		TypePub:       true,
		TypePyPi:      true,
		TypeRPM:       true,
		TypeSwift:     true,
	}

	// purl type is case-insensitive, canonical form is lower-case
	t = strings.ToLower(t)
	_, ok := types[t]
	return ok
}

// Qualifier names.
const (
	Distro        = "distro"
	Epoch         = "epoch"
	Arch          = "arch"
	Origin        = "origin"
	Source        = "source"
	SourceVersion = "sourceversion"
	SourceRPM     = "sourcerpm"
)
