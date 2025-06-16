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

// Package list provides a list of annotation plugins.
package list

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/annotator/cachedir"
	"github.com/google/osv-scalibr/annotator/osduplicate/dpkg"
	"github.com/google/osv-scalibr/annotator/osduplicate/rpm"
	"github.com/google/osv-scalibr/plugin"
)

// InitFn is the annotator initializer function.
type InitFn func() annotator.Annotator

// InitMap is a map of annotator names to their initers.
type InitMap map[string][]InitFn

// VEX generation related annotators.
var VEX = InitMap{cachedir.Name: {cachedir.New}, dpkg.Name: {dpkg.New}, rpm.Name: {rpm.NewDefault}}

// Default detectors that are recommended to be enabled.
var Default = InitMap{cachedir.Name: {cachedir.New}}

// All annotators.
var All = concat(
	VEX,
)

var annotatorNames = concat(All, InitMap{
	"vex":     vals(VEX),
	"default": vals(Default),
	"all":     vals(All),
})

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

// FromCapabilities returns all annotators that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []annotator.Annotator {
	all := []annotator.Annotator{}
	for _, initers := range All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	return FilterByCapabilities(all, capabs)
}

// FilterByCapabilities returns all annotators from the given list that can run
// under the specified capabilities (OS, direct filesystem access, network
// access, etc.) of the scanning environment.
func FilterByCapabilities(annotators []annotator.Annotator, capabs *plugin.Capabilities) []annotator.Annotator {
	result := []annotator.Annotator{}
	for _, a := range annotators {
		if err := plugin.ValidateRequirements(a, capabs); err == nil {
			result = append(result, a)
		}
	}
	return result
}

// AnnotatorsFromNames returns a deduplicated list of annotators from a list of names.
func AnnotatorsFromNames(names []string) ([]annotator.Annotator, error) {
	resultMap := make(map[string]annotator.Annotator)
	for _, n := range names {
		if initers, ok := annotatorNames[n]; ok {
			for _, initer := range initers {
				a := initer()
				if _, ok := resultMap[a.Name()]; !ok {
					resultMap[a.Name()] = a
				}
			}
		} else {
			return nil, fmt.Errorf("unknown annotator %q", n)
		}
	}
	result := make([]annotator.Annotator, 0, len(resultMap))
	for _, a := range resultMap {
		result = append(result, a)
	}
	return result, nil
}
