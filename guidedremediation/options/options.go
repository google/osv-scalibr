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

// Package options has the configuration options for guided remediation.
package options

import (
	"context"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/matcher"
	"github.com/google/osv-scalibr/guidedremediation/strategy"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

// DependencyCachePopulator is an interface for populating the cache of a resolve.Client.
// It is called before the initial resolution of a manifest, with the requirements of the manifest.
// The mechanism for populating the cache is up to the implementer to decide.
type DependencyCachePopulator interface {
	PopulateCache(ctx context.Context, c resolve.Client, requirements []resolve.RequirementVersion, manifestPath string)
}

// FixVulnsOptions are the options for guidedremediation.FixVulns().
type FixVulnsOptions struct {
	RemediationOptions

	Manifest          string                       // Path to manifest file on disk.
	Lockfile          string                       // Path to lockfile on disk.
	Strategy          strategy.Strategy            // Remediation strategy to use.
	MaxUpgrades       int                          // Maximum number of patches to apply. If <= 0 applies as many as possible.
	NoIntroduce       bool                         // If true, do not apply patches that introduce new vulnerabilities.
	NoMavenNewDepMgmt bool                         // If true, do not apply patches that introduce new dependency management.
	MatcherClient     matcher.VulnerabilityMatcher // Matcher for vulnerability information.
	ResolveClient     resolve.Client               // Client for dependency information.
	DefaultRepository string                       // Default registry to fetch dependency information from.
	DepCachePopulator DependencyCachePopulator     // Interface for populating the cache of the resolve.Client. Can be nil.
}

// RemediationOptions are the configuration options for vulnerability remediation.
type RemediationOptions struct {
	ResolutionOptions

	IgnoreVulns   []string // Vulnerability IDs to ignore
	ExplicitVulns []string // If set, only consider these vulnerability IDs & ignore all others

	DevDeps     bool    // Whether to consider vulnerabilities in dev dependencies
	MinSeverity float64 // Minimum vulnerability CVSS score to consider
	MaxDepth    int     // Maximum depth of dependency to consider vulnerabilities for (e.g. 1 for direct only)

	UpgradeConfig upgrade.Config // Allowed upgrade levels per package.

}

// DefaultRemediationOptions creates a default initialized remediation configuration.
func DefaultRemediationOptions() RemediationOptions {
	return RemediationOptions{
		DevDeps:       true,
		MaxDepth:      -1,
		UpgradeConfig: upgrade.NewConfig(),
	}
}

// ResolutionOptions are the configuration options for dependency resolution.
type ResolutionOptions struct {
	MavenManagement bool // Whether to include unresolved dependencyManagement dependencies in resolved graph.
}

// UpdateOptions are the options for performing guidedremediation.Update().
type UpdateOptions struct {
	Manifest          string         // Path to manifest file on disk.
	ResolveClient     resolve.Client // Client for dependency information.
	DefaultRepository string         // Default registry to fetch dependency information from.

	IgnoreDev     bool           // Whether to ignore updates on dev dependencies
	UpgradeConfig upgrade.Config // Allowed upgrade levels per package.
}
