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

// Package upgrade provides the configuration for the allowable package upgrade levels for remediation.
package upgrade

import (
	"strings"

	"deps.dev/util/semver"
)

// Level is the maximum semver level of upgrade allowed for a package.
// i.e. if Level == Major, all upgrades are allowed,
// if Level == Minor, only upgrades up to minor (1.0.0 - 1.*.*) are allowed.
type Level int

const (
	Major Level = iota
	Minor
	Patch
	None
)

// Allows returns if the semver.Diff is allowable for this upgrade level constraint.
func (level Level) Allows(diff semver.Diff) bool {
	if diff == semver.Same {
		return true
	}

	switch level {
	case Major:
		return true
	case Minor:
		return diff != semver.DiffMajor
	case Patch:
		return (diff != semver.DiffMajor) && (diff != semver.DiffMinor)
	case None:
		return false
	default: // Invalid level
		return false
	}
}

// Config hold the specified allowed Levels for each package in a manifest.
type Config map[string]Level

// NewConfig creates a new Config, with all packages allowing all upgrades.
func NewConfig() Config {
	return make(Config)
}

// NewConfigFromStrings creates a new Config from a list of strings.
// Each string is in the format of "pkg:level", where pkg is the package name and level is one of
// "major", "minor", "patch", or "none".
// If pkg is not specified, the level is set as the default level for all packages not specified.
// Invalid strings are ignored, duplicate package strings are overwritten.
func NewConfigFromStrings(cfgStrings []string) Config {
	cfg := NewConfig()
	for _, c := range cfgStrings {
		var pkg string
		level := c
		if idx := strings.LastIndex(c, ":"); idx != -1 {
			pkg = c[:idx]
			level = c[idx+1:]
		}
		switch level {
		case "major":
			cfg.Set(pkg, Major)
		case "minor":
			cfg.Set(pkg, Minor)
		case "patch":
			cfg.Set(pkg, Patch)
		case "none":
			cfg.Set(pkg, None)
			// Ignore invalid levels.
		}
	}

	return cfg
}

// Set the allowed upgrade level for a given pkg name.
// If level for pkg was previously set, sets the package to the new level and returns true.
// Otherwise, sets the package's level and returns false.
func (c Config) Set(pkg string, level Level) bool {
	_, alreadySet := c[pkg]
	c[pkg] = level

	return alreadySet
}

// SetDefault sets the default allowed upgrade level packages that weren't explicitly set.
// If default was previously set, sets the default to the new level and returns true.
// Otherwise, sets the default and returns false.
func (c Config) SetDefault(level Level) bool {
	// Empty package name is used as the default level.
	return c.Set("", level)
}

// Get the allowed Level for the given pkg name.
func (c Config) Get(pkg string) Level {
	if lvl, ok := c[pkg]; ok {
		return lvl
	}

	// Empty package name is used as the default level.
	return c[""]
}
