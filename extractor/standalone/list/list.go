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
		"extractors/default": vals(Default),
		"default":            vals(Default),
		"extractors/all":     vals(All),
		"all":                vals(All),
		"containers":         vals(Containers),
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

// ExtractorsFromName returns a list of extractors from a name.
func ExtractorsFromName(name string) ([]standalone.Extractor, error) {
	if initers, ok := extractorNames[name]; ok {
		result := []standalone.Extractor{}
		for _, initer := range initers {
			result = append(result, initer())
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown extractor %q", name)
}
