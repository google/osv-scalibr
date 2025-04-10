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

// Package suggest provides the functionality to suggest dependency update patch.
package suggest

import (
	"context"
	"errors"
	"fmt"

	"deps.dev/util/resolve"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// A PatchSuggester provides an ecosystem-specific method for 'suggesting'
// Patch for dependency updates.
type PatchSuggester interface {
	// Suggest returns the Patch required to update the dependencies to
	// a newer version based on the given options.
	Suggest(ctx context.Context, mf manifest.Manifest, opts options.UpdateOptions) (result.Patch, error)
}

// NewSuggester returns the PatchSuggester based on the specified ecosystem.
func NewSuggester(system resolve.System) (PatchSuggester, error) {
	switch system {
	case resolve.Maven:
		return &MavenSuggester{}, nil
	case resolve.NPM:
		return nil, errors.New("npm not yet supported")
	case resolve.PyPI:
		return nil, errors.New("PyPI not yet supported")
	case resolve.UnknownSystem:
		return nil, errors.New("unknown system")
	default:
		return nil, fmt.Errorf("unsupported ecosystem: %v", system)
	}
}
