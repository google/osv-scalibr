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

package resolution_test

import (
	"context"
	"testing"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/schema"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	mavenmanifest "github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/options"
)

// mockManifest represents a manifest file for testing purposes.
// It implements the manifest.Manifest interface.
type mockManifest struct {
	name              string
	version           string
	system            resolve.System
	requirements      []mockManifestRequirements
	groups            map[manifest.RequirementKey][]string
	localManifests    []mockManifest
	ecosystemSpecific any
}

type mockManifestRequirements struct {
	name    string
	version string
	typ     dep.Type
}

func (m mockManifest) FilePath() string {
	return ""
}

func (m mockManifest) Root() resolve.Version {
	return resolve.Version{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   m.name,
				System: m.system,
			},
			Version:     m.version,
			VersionType: resolve.Concrete,
		},
	}
}

func (m mockManifest) System() resolve.System {
	return m.system
}

func (m mockManifest) Requirements() []resolve.RequirementVersion {
	reqs := make([]resolve.RequirementVersion, len(m.requirements))
	for i, r := range m.requirements {
		reqs[i] = resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					Name:   r.name,
					System: m.system,
				},
				Version:     r.version,
				VersionType: resolve.Requirement,
			},
			Type: r.typ.Clone(),
		}
	}
	return reqs
}

func (m mockManifest) Groups() map[manifest.RequirementKey][]string {
	return m.groups
}

func (m mockManifest) LocalManifests() []manifest.Manifest {
	ret := make([]manifest.Manifest, len(m.localManifests))
	for i, lm := range m.localManifests {
		ret[i] = lm
	}
	return ret
}

func (m mockManifest) EcosystemSpecific() any {
	return m.ecosystemSpecific
}

func (m mockManifest) Clone() manifest.Manifest {
	return m
}

func (m mockManifest) PatchRequirement(resolve.RequirementVersion) error {
	return nil
}

func TestResolveNPM(t *testing.T) {
	aliasType := func(knownAs string) dep.Type {
		var typ dep.Type
		typ.AddAttr(dep.KnownAs, knownAs)
		return typ
	}
	// Create a mock manifest with dependencies, including aliases and workspaces.
	m := mockManifest{
		name:    "test",
		version: "1.0.0",
		system:  resolve.NPM,
		requirements: []mockManifestRequirements{
			{
				name:    "pkg",
				version: "^1.0.0",
			},
			{
				// Alias for "pkg"
				name:    "pkg",
				version: "^2.0.0",
				typ:     aliasType("pkg-aliased"),
			},
			{
				// Workspace dependency
				name:    "one:workspace",
				version: "*",
			},
			{
				// Workspace dependency
				name:    "two:workspace",
				version: "*",
			},
		},
		localManifests: []mockManifest{
			{
				name:    "one:workspace",
				version: "1.1.1",
				system:  resolve.NPM,
				requirements: []mockManifestRequirements{
					{
						name:    "two:workspace",
						version: "*",
					},
					{
						name:    "pkg",
						version: "^2.0.0",
					},
				},
			},
			{
				name:    "two:workspace",
				version: "2.2.2",
				system:  resolve.NPM,
				requirements: []mockManifestRequirements{
					{
						name:    "pkg",
						version: "^1.0.0",
					},
				},
			},
		},
	}
	cl := clienttest.NewMockResolutionClient(t, "testdata/universe/npm.yaml")

	got, err := resolution.Resolve(context.Background(), cl, m, options.ResolutionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Canon()
	got.Duration = 0 // Ignore duration for comparison

	want, err := schema.ParseResolve(`
test 1.0.0
	p1: Selector | pkg@^1.0.0 1.0.0
		p2: Selector | pkg2@^1.0.0 1.1.1
	KnownAs pkg-aliased Selector | pkg@^2.0.0 2.0.0
		$p2@^1.0.0
	Selector | one:workspace@* 1.1.1
		$ws2@*
		Selector | pkg@^2.0.0 2.0.0
			$p2@^1.0.0
	ws2: Selector | two:workspace@* 2.2.2
		$p1@^1.0.0
`, resolve.NPM)
	if err != nil {
		t.Fatal(err)
	}
	_ = want.Canon()
	want.Duration = 0

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Resolve() mismatch (-want +got):\n%s", diff)
	}
}

func TestResolveMaven(t *testing.T) {
	var managementType dep.Type
	managementType.AddAttr(dep.MavenDependencyOrigin, "management")
	m := mockManifest{
		name:    "test:test",
		version: "1.0.0",
		system:  resolve.Maven,
		requirements: []mockManifestRequirements{
			{
				name:    "group:pkg1",
				version: "1.0",
			},
			{
				// Dependency from dependencyManagement (used)
				name:    "group:pkg2",
				version: "2.0",
				typ:     managementType.Clone(),
			},
			{
				// Dependency from dependencyManagement (unused)
				name:    "group:pkg3",
				version: "3.0",
				typ:     managementType.Clone(),
			},
		},
		ecosystemSpecific: mavenmanifest.ManifestSpecific{
			// Construct the OriginalRequirements that resolvePostProcess checks.
			OriginalRequirements: []mavenmanifest.DependencyWithOrigin{
				{
					Dependency: maven.Dependency{
						GroupID:    "group",
						ArtifactID: "pkg1",
						Version:    "1.0",
					},
					Origin: "",
				},
				{
					Dependency: maven.Dependency{
						GroupID:    "group",
						ArtifactID: "pkg2",
						Version:    "2.0",
					},
					Origin: "management",
				},
				{
					Dependency: maven.Dependency{
						GroupID:    "group",
						ArtifactID: "pkg3",
						Version:    "3.0",
					},
					Origin: "management",
				},
			},
		},
	}
	cl := clienttest.NewMockResolutionClient(t, "testdata/universe/maven.yaml")

	got, err := resolution.Resolve(context.Background(), cl, m, options.ResolutionOptions{MavenManagement: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = got.Canon()
	got.Duration = 0

	want, err := schema.ParseResolve(`
test:test 1.0.0
	Selector | group:pkg1@1.0 1.0
		Selector | group:pkg2@2.0 2.0
	MavenDependencyOrigin management | group:pkg3@3.0 3.0
`, resolve.Maven)
	if err != nil {
		t.Fatal(err)
	}
	_ = want.Canon()
	want.Duration = 0

	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Resolve() mismatch (-want +got):\n%s", diff)
	}
}
