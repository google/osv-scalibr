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

// Package enricherlist provides methods to initialize enrichers from attributes like names or capabilities.
package enricherlist

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	"github.com/google/osv-scalibr/enricher/secrets"
	"github.com/google/osv-scalibr/plugin"
)

// InitFn is the enricher initializer function.
type InitFn func() enricher.Enricher

// InitMap is a map of names to enricher initializer functions.
type InitMap map[string][]InitFn

var (

	// LayerDetails enrichers.
	LayerDetails = InitMap{
		baseimage.Name: {baseimage.NewDefault},
	}

	// Secrets enrichers.
	Secrets = InitMap{
		secrets.Name: {secrets.New},
	}

	// Default enrichers.
	Default = concat()

	// All enrichers.
	All = concat(
		LayerDetails,
		Secrets,
	)

	enricherNames = concat(All, InitMap{
		"layerdetails": vals(LayerDetails),
		"secrets":      vals(Secrets),
		"default":      vals(Default),
		"all":          vals(All),
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
	return slices.Concat(slices.AppendSeq(make([][]InitFn, 0, len(initMap)), maps.Values(initMap))...)
}

// FromName returns a single extractor based on its exact name.
func FromName(name string) (enricher.Enricher, error) {
	initers, ok := enricherNames[name]
	if !ok {
		return nil, fmt.Errorf("unknown enricher %q", name)
	}
	if len(initers) != 1 {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	e := initers[0]()
	if e.Name() != name {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	return e, nil
}

// FromNames returns a list of enrichers from a list of names.
func FromNames(names []string) ([]enricher.Enricher, error) {
	resultMap := make(map[string]enricher.Enricher)
	for _, n := range names {
		if initers, ok := enricherNames[n]; ok {
			for _, initer := range initers {
				e := initer()
				if _, ok := resultMap[e.Name()]; !ok {
					resultMap[e.Name()] = e
				}
			}
		} else {
			return nil, fmt.Errorf("unknown enricher %q", n)
		}
	}
	if len(resultMap) == 0 {
		return nil, nil
	}
	result := make([]enricher.Enricher, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}

// FromCapabilities returns all enrichers that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabilities *plugin.Capabilities) []enricher.Enricher {
	var all []enricher.Enricher
	for _, initers := range All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	return FilterByCapabilities(all, capabilities)
}

// FilterByCapabilities returns all enrichers from the given list that can run
// under the specified capabilities (OS, direct filesystem access, network
// access, etc.) of the scanning environment.
func FilterByCapabilities(es []enricher.Enricher, capabilities *plugin.Capabilities) []enricher.Enricher {
	if capabilities == nil {
		capabilities = &plugin.Capabilities{}
	}

	var result []enricher.Enricher
	for _, e := range es {
		if err := plugin.ValidateRequirements(e, capabilities); err == nil {
			result = append(result, e)
		}
	}
	return result
}
