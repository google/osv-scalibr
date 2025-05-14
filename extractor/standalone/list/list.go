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
	"maps"
	"slices"

	"github.com/google/osv-scalibr/extractor/standalone"
	"github.com/google/osv-scalibr/extractor/standalone/containers/containerd"
	"github.com/google/osv-scalibr/extractor/standalone/containers/docker"
	"github.com/google/osv-scalibr/extractor/standalone/os/netports"
	"github.com/google/osv-scalibr/extractor/standalone/windows/dismpatch"
	"github.com/google/osv-scalibr/extractor/standalone/windows/ospackages"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regosversion"
	"github.com/google/osv-scalibr/extractor/standalone/windows/regpatchlevel"
	"github.com/google/osv-scalibr/plugin"
)

// InitFn is the extractor initializer function.
type InitFn func() standalone.Extractor

// InitMap is a map of extractor names to their initers.
type InitMap map[string][]InitFn

var (
	// Windows standalone extractors.
	Windows = InitMap{dismpatch.Name: {dismpatch.New}}

	// WindowsExperimental defines experimental extractors. Note that experimental does not mean
	// dangerous.
	WindowsExperimental = InitMap{
		ospackages.Name:    {ospackages.NewDefault},
		regosversion.Name:  {regosversion.NewDefault},
		regpatchlevel.Name: {regpatchlevel.NewDefault},
	}

	// OSExperimental defines experimental OS extractors.
	OSExperimental = InitMap{
		netports.Name: {netports.New},
	}

	// Containers standalone extractors.
	Containers = InitMap{
		containerd.Name: {containerd.NewDefault},
		docker.Name:     {docker.New},
	}

	// Default standalone extractors.
	Default = Windows
	// All standalone extractors.
	All = concat(Windows, WindowsExperimental, Containers, OSExperimental)

	extractorNames = concat(All, InitMap{
		// Windows
		"windows": vals(Windows),

		// Collections.
		"default":    vals(Default),
		"all":        vals(All),
		"containers": vals(Containers),
	})
)

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
func FromCapabilities(capabs *plugin.Capabilities) []standalone.Extractor {
	all := []standalone.Extractor{}
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
func FilterByCapabilities(exs []standalone.Extractor, capabs *plugin.Capabilities) []standalone.Extractor {
	result := []standalone.Extractor{}
	for _, ex := range exs {
		if err := plugin.ValidateRequirements(ex, capabs); err == nil {
			result = append(result, ex)
		}
	}
	return result
}

// ExtractorsFromNames returns a deduplicated list of extractors from a list of names.
func ExtractorsFromNames(names []string) ([]standalone.Extractor, error) {
	resultMap := make(map[string]standalone.Extractor)
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
	result := make([]standalone.Extractor, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}

// ExtractorFromName returns a single extractor based on its exact name.
func ExtractorFromName(name string) (standalone.Extractor, error) {
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
