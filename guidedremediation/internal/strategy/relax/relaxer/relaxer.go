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

// Package relaxer implements requirement specification relaxation for ecosystems.
package relaxer

import (
	"context"
	"errors"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

// A RequirementRelaxer provides an ecosystem-specific method for 'relaxing' the
// specified versions of dependencies for vulnerability remediation.
// Relaxing involves incrementally widening and bumping the version specifiers
// of the requirement to allow more recent versions to be selected during
// dependency resolution.
// It has access to the available versions of a package via a resolve client.
//
// e.g. in a semver-like ecosystem, relaxation could follow the sequence:
// 1.2.3 -> 1.2.* -> 1.*.* -> 2.*.* -> 3.*.* -> ...
type RequirementRelaxer interface {
	// Relax attempts to relax import requirement.
	// Returns the newly relaxed import and true it was successful.
	// If unsuccessful, it returns the original import and false.
	Relax(ctx context.Context, cl resolve.Client, req resolve.RequirementVersion, config upgrade.Config) (resolve.RequirementVersion, bool)
}

// ForEcosystem returns the RequirementRelaxer for the specified ecosystem.
func ForEcosystem(ecosystem resolve.System) (RequirementRelaxer, error) {
	switch ecosystem {
	case resolve.NPM:
		return NpmRelaxer{}, nil
	case resolve.PyPI:
		return PythonRelaxer{}, nil
	case resolve.Maven, resolve.UnknownSystem:
		fallthrough
	default:
		return nil, errors.New("unsupported ecosystem")
	}
}
