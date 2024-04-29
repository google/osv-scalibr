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
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/language/dotnet/packageslockjson"
	"github.com/google/osv-scalibr/extractor/language/golang/gobinary"
	javaarchive "github.com/google/osv-scalibr/extractor/language/java/archive"
	"github.com/google/osv-scalibr/extractor/language/javascript/packagejson"
	"github.com/google/osv-scalibr/extractor/language/javascript/packagelockjson"
	"github.com/google/osv-scalibr/extractor/language/python/requirements"
	"github.com/google/osv-scalibr/extractor/language/python/wheelegg"
	"github.com/google/osv-scalibr/extractor/language/ruby/gemspec"
	"github.com/google/osv-scalibr/extractor/os/apk"
	"github.com/google/osv-scalibr/extractor/os/cos"
	"github.com/google/osv-scalibr/extractor/os/dpkg"
	"github.com/google/osv-scalibr/extractor/os/rpm"
	"github.com/google/osv-scalibr/extractor/os/testractor"
	"github.com/google/osv-scalibr/extractor/osv"
	"github.com/google/osv-scalibr/extractor/sbom/spdx"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/purl"
	"github.com/google/osv-scanner/pkg/lockfile"
)

// LINT.IfChange
var (
	// Language extractors.

	// Java extractors.
	Java []extractor.InventoryExtractor = []extractor.InventoryExtractor{javaarchive.New(javaarchive.DefaultConfig())}
	// Javascript extractors.
	Javascript []extractor.InventoryExtractor = []extractor.InventoryExtractor{packagejson.New(packagejson.DefaultConfig()), &packagelockjson.Extractor{}}
	// Python extractors.
	Python []extractor.InventoryExtractor = []extractor.InventoryExtractor{wheelegg.New(wheelegg.DefaultConfig()), &requirements.Extractor{}}
	// Go extractors.
	Go []extractor.InventoryExtractor = []extractor.InventoryExtractor{&gobinary.Extractor{}}
	// Ruby extractors.
	Ruby []extractor.InventoryExtractor = []extractor.InventoryExtractor{&gemspec.Extractor{}}
	// SBOM extractors.
	SBOM []extractor.InventoryExtractor = []extractor.InventoryExtractor{&spdx.Extractor{}}
	// Dotnet (.NET) extractors.
	Dotnet []extractor.InventoryExtractor = []extractor.InventoryExtractor{&packageslockjson.Extractor{}}

	// OS extractors.
	OS []extractor.InventoryExtractor = []extractor.InventoryExtractor{
		dpkg.New(dpkg.DefaultConfig()),
		&apk.Extractor{},
		rpm.New(rpm.DefaultConfig()),
		&cos.Extractor{},
		&testractor.Extractor{},
	}

	// Collections of extractors.

	// Default extractors that are recommended to be enabled.
	Default []extractor.InventoryExtractor = concat(Java, Javascript, Python, Go, OS)
	// All extractors available from SCALIBR. These don't include the untested extractors which can be enabled manually.
	All []extractor.InventoryExtractor = concat(
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
	Untested []extractor.InventoryExtractor = []extractor.InventoryExtractor{
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

	extractorNames = map[string][]extractor.InventoryExtractor{
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
	}
)

// LINT.ThenChange(/docs/supported_inventory_types.md)

func init() {
	for _, e := range append(All, Untested...) {
		register(e)
	}
}

// register adds the individual extractors to the extractorNames map.
func register(d extractor.InventoryExtractor) {
	if _, ok := extractorNames[strings.ToLower(d.Name())]; ok {
		log.Errorf("There are 2 extractors with the name: %q", d.Name())
		os.Exit(1)
	}
	extractorNames[strings.ToLower(d.Name())] = []extractor.InventoryExtractor{d}
}

// ExtractorsFromNames returns a deduplicated list of extractors from a list of names.
func ExtractorsFromNames(names []string) ([]extractor.InventoryExtractor, error) {
	resultMap := make(map[string]extractor.InventoryExtractor)
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
	result := make([]extractor.InventoryExtractor, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}

// ExtractorFromName returns a single extractor based on its exact name.
func ExtractorFromName(name string) (extractor.InventoryExtractor, error) {
	es, ok := extractorNames[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %s", name)
	}
	if len(es) != 1 || es[0].Name() != name {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	return es[0], nil
}

// Returns a new slice that concatenates the values of two or more slices without modifying them.
func concat(exs ...[]extractor.InventoryExtractor) []extractor.InventoryExtractor {
	length := 0
	for _, e := range exs {
		length += len(e)
	}
	result := make([]extractor.InventoryExtractor, 0, length)
	for _, e := range exs {
		result = append(result, e...)
	}
	return result
}
