// Copyright 2026 Google LLC
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

package internal

import (
	"context"
	"fmt"

	"deps.dev/util/resolve"
)

// PackageExtractor extracts a DirectDependency from a generic package type.
//
// All implementations must return equivalent outputs for equivalent inputs.
type PackageExtractor[T comparable] interface {
	Extract(pkg T) *DirectDependency
}

// OfflineSolver is a dependency constraint solver operating on a set of local (generic) packages.
//
// This is not a general-purpose API! It is designed specifically for offline resolution, with the
// assumption that the scan input is an artifacts bundling *complete* dependency metadata. It will
// not consult any external data source, and only resolve dependencies within the input set.
//
// The mapping between dependencies and [T] instances is subject to the regular Go equality rules.
// Pay particular attention when [T] is a pointer type: those are compared by reference, not value!
type OfflineSolver[T comparable] struct {
	client *resolve.LocalClient
	// packages maps version keys, as resolved by the client, to the input packages they were
	// associated with. The mapping is user-determined, based on the [PackageExtractor] in use.
	packages map[resolve.VersionKey][]T
	// keys maps every package to its resolved version key. It's the inverse of the packages map.
	keys map[T]resolve.VersionKey
}

// NewOfflineSolver creates a new [OfflineSolver] from a list of (generic) packages.
func NewOfflineSolver[T comparable](pkgs []T, extractor PackageExtractor[T]) (*OfflineSolver[T], error) {
	solver := &OfflineSolver[T]{
		client:   resolve.NewLocalClient(),
		packages: make(map[resolve.VersionKey][]T, len(pkgs)),
		keys:     make(map[T]resolve.VersionKey, len(pkgs)),
	}
	for _, pkg := range pkgs {
		metadata := extractor.Extract(pkg)
		if metadata == nil {
			continue
		}
		key := metadata.Version.VersionKey
		solver.client.AddVersion(metadata.Version, metadata.Requirements)
		solver.packages[key] = append(solver.packages[key], pkg)
		solver.keys[pkg] = key
	}
	return solver, nil
}

// Requirements returns the direct dependency constraints declared by the given package.
//
// If the package is not known, the solver will return an error.
func (s *OfflineSolver[T]) Requirements(ctx context.Context, pkg T) ([]resolve.RequirementVersion, error) {
	key, ok := s.keys[pkg]
	if !ok {
		return nil, fmt.Errorf("package %v: %w", pkg, resolve.ErrNotFound)
	}
	return s.client.Requirements(ctx, key)
}

// Solve returns all known packages that match the given dependency constraint.
//
// If no version constraint is set for a dependency, the solver returns all known versions.
func (s *OfflineSolver[T]) Solve(ctx context.Context, req resolve.RequirementVersion) ([]T, error) {
	var versions []resolve.Version
	var err error
	if req.Version == "" {
		versions, err = s.client.Versions(ctx, req.PackageKey)
	} else {
		versions, err = s.client.MatchingVersions(ctx, req.VersionKey)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to solve %s: %w", req, err)
	}

	var resolved []T
	for _, v := range versions {
		packages, ok := s.packages[v.VersionKey]
		if !ok {
			return nil, fmt.Errorf("missing mapping for %v, this should never happen", v)
		}
		resolved = append(resolved, packages...)
	}
	return resolved, nil
}
