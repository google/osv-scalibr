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

// Package list contains the list of all standalone extractors.
package list

import (
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/extractor/standalone/windows/ospackages"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regosversion"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regpatchlevel"
	"github.com/google/osv-scalibr/log"
	"github.com/google/osv-scalibr/plugin"
)

var (
	// Windows standalone extractors.
	Windows = []standalone.Extractor{
		&dismpatch.Extractor{},
	}

	// WindowsExperimental defines experimental extractors. Note that experimental does not mean
	// dangerous.
	WindowsExperimental = []standalone.Extractor{
		ospackages.New(ospackages.DefaultConfiguration()),
		regosversion.New(regosversion.DefaultConfiguration()),
		regpatchlevel.New(regpatchlevel.DefaultConfiguration()),
	}

	// Containers standalone extractors.
	Containers = []standalone.Extractor{
		containerd.New(containerd.DefaultConfig()),
	}

	// Default standalone extractors.
	Default []standalone.Extractor = slices.Concat(Windows)
	// All standalone extractors.
	All []standalone.Extractor = slices.Concat(Windows, WindowsExperimental, Containers)

	extractorNames = map[string][]standalone.Extractor{
		// Windows
		"windows": Windows,

		// Collections.
		"default":    Default,
		"all":        All,
		"containers": Containers,
	}
)

//nolint:gochecknoinits
func init() {
	for _, e := range All {
		register(e)
	}
}

// register adds the individual extractors to the extractorNames map.
func register(d standalone.Extractor) {
	if _, ok := extractorNames[strings.ToLower(d.Name())]; ok {
		log.Errorf("There are 2 extractors with the name: %q", d.Name())
		os.Exit(1)
	}

	extractorNames[strings.ToLower(d.Name())] = []standalone.Extractor{d}
}

// FromCapabilities returns all extractors that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []standalone.Extractor {
	return FilterByCapabilities(All, capabs)
}

// FilterByCapabilities returns all extractors from the given list that can run
// under the specified capabilities (OS, direct filesystem access, network
// access, etc.) of the scanning environment.
func FilterByCapabilities(exs []standalone.Extractor, capabs *plugin.Capabilities) []standalone.Extractor {
	result := []standalone.Extractor{}
	for _, ex := range exs {
		if err := plugin.ValidateRequirements(ex, capabs); err == nil {
			result = append(result, ex)
		}
	}
	return result
}

// ExtractorFromName returns a single extractor based on its exact name.
func ExtractorFromName(name string) (standalone.Extractor, error) {
	es, ok := extractorNames[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("unknown extractor %s", name)
	}
	if len(es) != 1 || es[0].Name() != name {
		return nil, fmt.Errorf("not an exact name for an extractor: %s", name)
	}
	return es[0], nil
}

// ExtractorsFromNames returns a deduplicated list of extractors from a list of names.
func ExtractorsFromNames(names []string) ([]standalone.Extractor, error) {
	resultMap := make(map[string]standalone.Extractor)
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
	result := make([]standalone.Extractor, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}
