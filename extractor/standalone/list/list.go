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

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// InitFn is the extractor initializer function.
type InitFn func(cfg *cpb.PluginConfig) (standalone.Extractor, error)

// InitMap is a map of extractor names to their initers.
type InitMap map[string][]InitFn

var (
	// Windows standalone extractors.
	Windows = InitMap{dismpatch.Name: {noCFG(dismpatch.New)}}

	// WindowsExperimental defines experimental extractors. Note that experimental does not mean
	// dangerous.
	WindowsExperimental = InitMap{
		ospackages.Name:    {noCFG(ospackages.NewDefault)},
		regosversion.Name:  {noCFG(regosversion.NewDefault)},
		regpatchlevel.Name: {noCFG(regpatchlevel.NewDefault)},
	}

	// OSExperimental defines experimental OS extractors.
	OSExperimental = InitMap{
		netports.Name: {noCFG(netports.New)},
	}

	// Containers standalone extractors.
	Containers = InitMap{
		containerd.Name: {noCFG(containerd.NewDefault)},
		docker.Name:     {noCFG(docker.New)},
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

// Wraps initer functions that don't take any config value to initer functions that do.
// TODO(b/400910349): Remove once all plugins take config values.
func noCFG(f func() standalone.Extractor) InitFn {
	return func(_ *cpb.PluginConfig) (standalone.Extractor, error) { return f(), nil }
}

// ExtractorsFromName returns a list of extractors from a name.
func ExtractorsFromName(name string, cfg *cpb.PluginConfig) ([]standalone.Extractor, error) {
	if initers, ok := extractorNames[name]; ok {
		result := []standalone.Extractor{}
		for _, initer := range initers {
			p, err := initer(cfg)
			if err != nil {
				return nil, err
			}
			result = append(result, p)
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown extractor %q", name)
}
