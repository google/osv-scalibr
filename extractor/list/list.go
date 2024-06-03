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

// Package list provides a public list of SCALIBR extraction plugins.
//
// It contains both filesystem and standalone extractors.
//
// All individual extractors are available through their unique names. In addition, there are groups
// of extractors such as e.g. "javascript" that bundle related extractors together.
package list

import (
	"fmt"
	"os"
	"slices"
	"strings"

	// OSV extractors.
	"github.com/google/osv-scanner/pkg/lockfile"

	// SCALIBR internal extractors.
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/golang/gobinary"
	javaarchive "github.com/google/osv-scalibr/extractor/filesystem/language/java/archive"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/filesystem/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/filesystem/language/ruby/gemspec"
	"github.com/google/osv-scalibr/extractor/filesystem/os/apk"
	"github.com/google/osv-scalibr/extractor/filesystem/os/cos"
	"github.com/google/osv-scalibr/extractor/filesystem/os/dpkg"
	"github.com/google/osv-scalibr/extractor/filesystem/os/rpm"
	"github.com/google/osv-scalibr/extractor/filesystem/osv"
	"github.com/google/osv-scalibr/extractor/filesystem/sbom/spdx"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"

)

// LINT.IfChange
var (
	// Language extractors.

	// Java extractors.
	Java []extractor.Extractor = []extractor.Extractor{javaarchive.New(javaarchive.DefaultConfig())}
	// Javascript extractors.
	Javascript []extractor.Extractor = []extractor.Extractor{
		packagejson.New(packagejson.DefaultConfig()),
		&packagelockjson.Extractor{},
	}
	// Python extractors.
	Python []extractor.Extractor = []extractor.Extractor{
		wheelegg.New(wheelegg.DefaultConfig()),
		&requirements.Extractor{},
	}
	// Go extractors.
	Go []extractor.Extractor = []extractor.Extractor{&gobinary.Extractor{}}
	// Ruby extractors.
	Ruby []extractor.Extractor = []extractor.Extractor{&gemspec.Extractor{}}
	// SBOM extractors.
	SBOM []extractor.Extractor = []extractor.Extractor{&spdx.Extractor{}}
	// Dotnet (.NET) extractors.
	Dotnet []extractor.Extractor = []extractor.Extractor{&packageslockjson.Extractor{}}

	// OS extractors.
	OS []extractor.Extractor = []extractor.Extractor{
		dpkg.New(dpkg.DefaultConfig()),
		&apk.Extractor{},
		rpm.New(rpm.DefaultConfig()),
		&cos.Extractor{},
	}

	// Collections of extractors.

	// Default extractors that are recommended to be enabled.
	Default []extractor.Extractor = slices.Concat(Java, Javascript, Python, Go, OS)
	// All extractors available from SCALIBR. These don't include the untested extractors which can be enabled manually.
	All []extractor.Extractor = slices.Concat(
		Java,
		Javascript,
		Python,
		Go,
		Ruby,
		Dotnet,
		SBOM,
		OS,
	)

	// Untested extractors are OSV extractors without tests.
	// TODO(b/307735923): Add tests for these and move them into All.
	Untested []extractor.Extractor = []extractor.Extractor{
		osv.Wrapper{ExtractorName: "cpp/conan", ExtractorVersion: 0, PURLType: purl.TypeConan, Extractor: lockfile.ConanLockExtractor{}},
		osv.Wrapper{ExtractorName: "dart/pubspec", ExtractorVersion: 0, PURLType: purl.TypePub, Extractor: lockfile.PubspecLockExtractor{}},
		osv.Wrapper{ExtractorName: "go/gomod", ExtractorVersion: 0, PURLType: purl.TypeGolang, Extractor: lockfile.GoLockExtractor{}},
		osv.Wrapper{ExtractorName: "java/gradle", ExtractorVersion: 0, PURLType: purl.TypeMaven, Extractor: lockfile.GradleLockExtractor{}},
		osv.Wrapper{ExtractorName: "java/pomxml", ExtractorVersion: 0, PURLType: purl.TypeMaven, Extractor: lockfile.MavenLockExtractor{}},
		osv.Wrapper{ExtractorName: "javascript/pnpm", ExtractorVersion: 0, PURLType: purl.TypeNPM, Extractor: lockfile.PnpmLockExtractor{}},
		osv.Wrapper{ExtractorName: "javascript/yarn", ExtractorVersion: 0, PURLType: purl.TypeNPM, Extractor: lockfile.YarnLockExtractor{}},
		osv.Wrapper{ExtractorName: "php/composer", ExtractorVersion: 0, PURLType: purl.TypeComposer, Extractor: lockfile.ComposerLockExtractor{}},
		osv.Wrapper{ExtractorName: "python/Pipfile", ExtractorVersion: 0, PURLType: purl.TypePyPi, Extractor: lockfile.PipenvLockExtractor{}},
		osv.Wrapper{ExtractorName: "python/poetry", ExtractorVersion: 0, PURLType: purl.TypePyPi, Extractor: lockfile.PoetryLockExtractor{}},
		osv.Wrapper{ExtractorName: "ruby/gemfile", ExtractorVersion: 0, PURLType: purl.TypeGem, Extractor: lockfile.GemfileLockExtractor{}},
		osv.Wrapper{ExtractorName: "rust/cargo", ExtractorVersion: 0, PURLType: purl.TypeCargo, Extractor: lockfile.CargoLockExtractor{}},
	}

	// Standalone extractors.
	Windows    []extractor.Extractor = []extractor.Extractor{&dismpatch.Extractor{}}
	Standalone []extractor.Extractor = slices.Concat(
		Windows,
	)

	extractors = map[string][]extractor.Extractor{
		// Languages.
		"java":       Java,
		"javascript": Javascript,
		"python":     Python,
		"go":         Go,
		"ruby":       Ruby,
		"dotnet":     Dotnet,

		"sbom": SBOM,
		"os":   OS,

		// Collections.
		"default":  Default,
		"all":      All,
		"untested": Untested,

		// Standalone.
		"windows": Windows,
	}
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

func init() {
	for _, e := range slices.Concat(All, Untested, Standalone) {
		register(e)
	}
}

// register adds an individual extractor to the extractors map.
func register(d extractor.Extractor) {
	if _, ok := extractors[strings.ToLower(d.Name())]; ok {
		log.Errorf("There are 2 extractors with the name: %q", d.Name())
		os.Exit(1)
	}
	extractors[strings.ToLower(d.Name())] = []extractor.Extractor{d}
}

// ExtractorsFromNames returns a deduplicated list of extractors given a list of names.
// Those names can be shorthands for groups of extractors like "javascript" or refer to specific
// extractors by their unique name.
func ExtractorsFromNames(names []string) ([]extractor.Extractor, error) {
	seen := map[string]struct{}{}
	result := []extractor.Extractor{}
	for _, n := range names {
		es, ok := extractors[strings.ToLower(n)]
		if !ok {
			return nil, fmt.Errorf("unknown extractor %q", n)
		}
		for _, e := range es {
			if _, ok := seen[e.Name()]; ok {
				continue
			}
			seen[e.Name()] = struct{}{}
			result = append(result, e)
		}
	}
	return result, nil
}

// ExtractorFromName returns a single extractor based on its unique name.
func ExtractorFromName(name string) (extractor.Extractor, error) {
	es, ok := extractors[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %s", name)
	}
	if len(es) != 1 || es[0].Name() != name {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	return es[0], nil
}

// SpecificExtractorsFromNames returns a deduplicated list of extractors that conform to type T
// given a list of names.
//
// Those names can be shorthands for groups of extractors like "javascript" or refer to specific
// extractors by their unique name.
//
// If strict is false, an extractor with a listed name that does not conform to T, it is silently
// omitted from the result.
// If strict is true, an error is returned instead.
func SpecificExtractorsFromNames[T extractor.Extractor](names []string, strict bool) ([]T, error) {
	es, err := ExtractorsFromNames(names)
	if err != nil {
		return nil, err
	}
	esT := []T{}
	for _, e := range es {
		eT, ok := e.(T)
		if !ok {
			if strict {
				return nil, fmt.Errorf("extractor %q does not conform to %T, is %T", e.Name(), *new(T), e)
			}
			continue
		}
		esT = append(esT, eT)
	}
	return esT, nil
}
