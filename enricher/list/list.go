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

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/plugin"
)

// InitFn is the enricher initializer function.
type InitFn func() enricher.Enricher

// InitMap is a map of names to enricher initializer functions.
type InitMap map[string][]InitFn

var (
	// All enrichers.
	All = InitMap{}
)

// FromNames returns a list of enrichers from a list of names.
func FromNames(names []string) ([]enricher.Enricher, error) {
	if len(names) == 0 {
		return nil, nil
	}
	return nil, fmt.Errorf("not implemented")
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
	var result []enricher.Enricher
	for _, e := range es {
		if err := plugin.ValidateRequirements(e, capabilities); err == nil {
			result = append(result, e)
		}
	}
	return result
}
