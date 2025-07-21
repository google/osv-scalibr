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

// Package list provides a functions for accessing SCALIBR-specific plugins from their respective type-specific lists.
package list

import (
	"fmt"

	"github.com/google/osv-scalibr/annotator"
	al "github.com/google/osv-scalibr/annotator/list"
	"github.com/google/osv-scalibr/detector"
	dl "github.com/google/osv-scalibr/detector/list"
	"github.com/google/osv-scalibr/enricher"
	el "github.com/google/osv-scalibr/enricher/enricherlist"
	"github.com/google/osv-scalibr/extractor/filesystem"
	fl "github.com/google/osv-scalibr/extractor/filesystem/list"
	"github.com/google/osv-scalibr/extractor/standalone"
	sl "github.com/google/osv-scalibr/extractor/standalone/list"
	"github.com/google/osv-scalibr/plugin"
)

// FromCapabilities returns all plugins that can run under the specified
// capabilities (OS, direct filesystem access, network access, etc.) of the
// scanning environment.
func FromCapabilities(capabs *plugin.Capabilities) []plugin.Plugin {
	return plugin.FilterByCapabilities(All(), capabs)
}

// FromNames returns a deduplicated list of plugins from a list of names.
func FromNames(names []string) ([]plugin.Plugin, error) {
	resultMap := make(map[string]plugin.Plugin)
	for _, name := range names {
		fsex, ferr := fl.ExtractorsFromName(name)
		stex, serr := sl.ExtractorsFromName(name)
		det, derr := dl.DetectorsFromName(name)
		ann, aerr := al.AnnotatorsFromName(name)
		enr, eerr := el.EnrichersFromName(name)

		// Report an error if none of the type-specific lists were able to resolve the name.
		if ferr != nil && serr != nil && derr != nil && aerr != nil && eerr != nil {
			return nil, fmt.Errorf("unknown plugin %q", name)
		}

		for _, p := range fsex {
			resultMap[p.Name()] = p
		}
		for _, p := range stex {
			resultMap[p.Name()] = p
		}
		for _, p := range det {
			resultMap[p.Name()] = p
		}
		for _, p := range ann {
			resultMap[p.Name()] = p
		}
		for _, p := range enr {
			resultMap[p.Name()] = p
		}
	}

	result := make([]plugin.Plugin, 0, len(resultMap))
	for _, e := range resultMap {
		result = append(result, e)
	}
	return result, nil
}

// FromName returns a single plugin based on its exact name.
func FromName(name string) (plugin.Plugin, error) {
	plugins, err := FromNames([]string{name})
	if err != nil {
		return nil, err
	}
	if len(plugins) != 1 {
		return nil, fmt.Errorf("not an exact name for a plugin: %q", name)
	}
	return plugins[0], nil
}

// All returns all plugins defined in their type-specific list files.
// Note that these plugins have different capability Requirements and can't all
// be run on the same host (e.g. some are Linux-only while others are Windows-only)
// Prefer using FromCapabilities instead.
func All() []plugin.Plugin {
	all := []plugin.Plugin{}
	for _, initers := range fl.All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	for _, initers := range sl.All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	for _, initers := range dl.All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	for _, initers := range al.All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	for _, initers := range el.All {
		for _, initer := range initers {
			all = append(all, initer())
		}
	}
	return all
}

// FilesystemExtractors returns the plugins from a list which are filesystem Extractors.
func FilesystemExtractors(plugins []plugin.Plugin) []filesystem.Extractor {
	result := []filesystem.Extractor{}
	for _, p := range plugins {
		if p, ok := p.(filesystem.Extractor); ok {
			result = append(result, p)
		}
	}
	return result
}

// StandaloneExtractors returns the plugins from a list which are standalone Extractors.
func StandaloneExtractors(plugins []plugin.Plugin) []standalone.Extractor {
	result := []standalone.Extractor{}
	for _, p := range plugins {
		if p, ok := p.(standalone.Extractor); ok {
			result = append(result, p)
		}
	}
	return result
}

// Detectors returns the plugins from a list which are Detectors.
func Detectors(plugins []plugin.Plugin) []detector.Detector {
	result := []detector.Detector{}
	for _, p := range plugins {
		if p, ok := p.(detector.Detector); ok {
			result = append(result, p)
		}
	}
	return result
}

// Annotators returns the plugins from a list which are Annotators.
func Annotators(plugins []plugin.Plugin) []annotator.Annotator {
	result := []annotator.Annotator{}
	for _, p := range plugins {
		if p, ok := p.(annotator.Annotator); ok {
			result = append(result, p)
		}
	}
	return result
}

// Enrichers returns the plugins from a list which are Enrichers.
func Enrichers(plugins []plugin.Plugin) []enricher.Enricher {
	result := []enricher.Enricher{}
	for _, p := range plugins {
		if p, ok := p.(enricher.Enricher); ok {
			result = append(result, p)
		}
	}
	return result
}
