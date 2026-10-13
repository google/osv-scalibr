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

package internal_test

import (
	"errors"
	"testing"

	"deps.dev/util/resolve"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher/transitivedependency/internal"
)

func TestPackageUnwrapFn(t *testing.T) {
	want := directDependency("bar", "1.0.0")

	solver, err := internal.NewOfflineSolver([]*fakePackage{{nil}, {want}}, &fakePackageExtractor{})
	if err != nil {
		t.Fatalf("NewOfflineSolver failed: %v", err)
	}

	got, err := solver.Solve(t.Context(), requirement("bar", "1.0.0"))
	if err != nil {
		t.Fatalf("Solve failed: %v", err)
	}

	if diff := cmp.Diff([]*fakePackage{{want}}, got); diff != "" {
		t.Errorf("NewOfflineSolver returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestRequirements(t *testing.T) {
	pkgFoo := &fakePackage{
		directDependency("foo", "1.0.0", requirement("bar", "1.0.0")),
	}
	pkgBar := &fakePackage{directDependency("bar", "1.0.0")}
	pkgBaz := &fakePackage{directDependency("baz", "1.0.0")}

	testCases := []struct {
		name     string
		packages []*fakePackage
		req      *fakePackage
		want     []resolve.RequirementVersion
		wantErr  error
	}{
		{
			name:     "empty",
			packages: nil,
			req:      pkgFoo,
			wantErr:  resolve.ErrNotFound,
		},
		{
			name:     "no_requirements",
			packages: []*fakePackage{pkgBaz},
			req:      pkgBaz,
			want:     nil,
		},
		{
			name:     "has_requirements",
			packages: []*fakePackage{pkgFoo, pkgBar},
			req:      pkgFoo,
			want: []resolve.RequirementVersion{
				requirement("bar", "1.0.0"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			solver, err := internal.NewOfflineSolver(tc.packages, &fakePackageExtractor{})
			if err != nil {
				t.Fatalf("NewSolver failed: %v", err)
			}

			got, err := solver.Requirements(t.Context(), tc.req)
			if !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Requirements error: got %v, want %v", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Requirements returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSolve(t *testing.T) {
	testCases := []struct {
		name         string
		packages     []*fakePackage
		req          resolve.RequirementVersion
		want         []*fakePackage
		wantNotFound bool
	}{
		{
			name:         "empty",
			packages:     nil,
			req:          requirement("foo", "1.0.0"),
			wantNotFound: true,
		},
		{
			name: "full_match",
			packages: []*fakePackage{
				{directDependency("foo", "1.0.0")},
				{directDependency("foo", "2.1.3")},
				{directDependency("bar", "5.0.0")},
			},
			req: requirement("foo", ">=2.0.0"),
			want: []*fakePackage{{
				directDependency("foo", "2.1.3"),
			}},
		},
		{
			name: "not_found",
			packages: []*fakePackage{
				{directDependency("foo", "1.0.0")},
				{directDependency("foo", "2.1.3")},
				{directDependency("bar", "5.0.0")},
			},
			req:          requirement("baz", ""),
			wantNotFound: true,
		},
		{
			name: "unsatisfiable_match",
			packages: []*fakePackage{
				{directDependency("foo", "1.0.0")},
				{directDependency("foo", "2.0.0")},
				{directDependency("bar", "5.0.0")},
			},
			req: requirement("foo", "4.0.0"),
			// The solver knew about this package, but the required constraint was unsatisfiable.
			// Same as if the package was not known to the solver at all.
			want: nil,
		},
		{
			name: "no_version_match",
			packages: []*fakePackage{
				{directDependency("foo", "1.0.0")},
				{directDependency("foo", "2.0.0")},
				{directDependency("bar", "5.0.0")},
			},
			req: requirement("foo", ""),
			// The solver was not given any restriction on the version, so it returned all known ones.
			want: []*fakePackage{
				{directDependency("foo", "1.0.0")},
				{directDependency("foo", "2.0.0")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			solver, err := internal.NewOfflineSolver(tc.packages, &fakePackageExtractor{})
			if err != nil {
				t.Fatalf("NewSolver failed: %v", err)
			}

			got, err := solver.Solve(t.Context(), tc.req)
			if tc.wantNotFound && !errors.Is(err, resolve.ErrNotFound) {
				t.Fatalf("Solve expected ErrNotFound, got: %v", err)
			}
			if !tc.wantNotFound && err != nil {
				t.Fatalf("Solve failed: %v", err)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("Solve returned unexpected diff (-want +got):\n%s", diff)
			}
		})
	}
}

type fakePackage struct {
	Dependency *internal.DirectDependency
}

type fakePackageExtractor struct{}

func (*fakePackageExtractor) Extract(pkg *fakePackage) *internal.DirectDependency {
	return pkg.Dependency
}

func directDependency(name, version string, requirements ...resolve.RequirementVersion) *internal.DirectDependency {
	return &internal.DirectDependency{
		Version: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  resolve.PackageKey{System: resolve.NPM, Name: name},
				VersionType: resolve.Concrete,
				Version:     version,
			},
		},
		Requirements: requirements,
	}
}

func requirement(name, version string) resolve.RequirementVersion {
	return resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey:  resolve.PackageKey{System: resolve.NPM, Name: name},
			VersionType: resolve.Requirement,
			Version:     version,
		},
	}
}
