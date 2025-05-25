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

package suggest

import (
	"context"
	"reflect"
	"sort"
	"testing"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	mavenmanifest "github.com/google/osv-scalibr/guidedremediation/internal/manifest/maven"
	"github.com/google/osv-scalibr/guidedremediation/options"
	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scalibr/guidedremediation/upgrade"
)

var (
	depMgmt           = depTypeWithOrigin("management")
	depParent         = depTypeWithOrigin("parent")
	depPlugin         = depTypeWithOrigin("plugin@org.plugin:plugin")
	depProfileOne     = depTypeWithOrigin("profile@profile-one")
	depProfileTwoMgmt = depTypeWithOrigin("profile@profile-two@management")
)

func depTypeWithOrigin(origin string) dep.Type {
	var result dep.Type
	result.AddAttr(dep.MavenDependencyOrigin, origin)

	return result
}

func mavenReqKey(t *testing.T, name, artifactType, classifier string) manifest.RequirementKey {
	t.Helper()
	var typ dep.Type
	if artifactType != "" {
		typ.AddAttr(dep.MavenArtifactType, artifactType)
	}
	if classifier != "" {
		typ.AddAttr(dep.MavenClassifier, classifier)
	}

	return mavenmanifest.MakeRequirementKey(resolve.RequirementVersion{
		VersionKey: resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				Name:   name,
				System: resolve.Maven,
			},
		},
		Type: typ,
	})
}

type testManifest struct {
	filePath          string
	root              resolve.Version
	system            resolve.System
	requirements      []resolve.RequirementVersion
	groups            map[manifest.RequirementKey][]string
	ecosystemSpecific mavenmanifest.ManifestSpecific
}

// FilePath returns the path to the manifest file.
func (m testManifest) FilePath() string {
	return m.filePath
}

// Root returns the Version representing this package.
func (m testManifest) Root() resolve.Version {
	return m.root
}

// System returns the ecosystem of this manifest.
func (m testManifest) System() resolve.System {
	return m.system
}

// Requirements returns all direct requirements (including dev).
func (m testManifest) Requirements() []resolve.RequirementVersion {
	return m.requirements
}

// Groups returns the dependency groups that the direct requirements belong to.
func (m testManifest) Groups() map[manifest.RequirementKey][]string {
	return m.groups
}

// LocalManifests returns Manifests of any local packages.
func (m testManifest) LocalManifests() []manifest.Manifest {
	return nil
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m testManifest) EcosystemSpecific() any {
	return m.ecosystemSpecific
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m testManifest) PatchRequirement(req resolve.RequirementVersion) error {
	return nil
}

// EcosystemSpecific returns any ecosystem-specific information for this manifest.
func (m testManifest) Clone() manifest.Manifest {
	return nil
}

func TestMavenSuggester_Suggest(t *testing.T) {
	ctx := context.Background()
	client := resolve.NewLocalClient()
	addVersions := func(sys resolve.System, name string, versions []string) {
		for _, version := range versions {
			client.AddVersion(resolve.Version{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: sys,
						Name:   name,
					},
					VersionType: resolve.Concrete,
					Version:     version,
				}}, nil)
		}
	}
	addVersions(resolve.Maven, "com.mycompany.app:parent-pom", []string{"1.0.0"})
	addVersions(resolve.Maven, "junit:junit", []string{"4.11", "4.12", "4.13", "4.13.2"})
	addVersions(resolve.Maven, "org.example:abc", []string{"1.0.0", "1.0.1", "1.0.2"})
	addVersions(resolve.Maven, "org.example:no-updates", []string{"9.9.9", "10.0.0"})
	addVersions(resolve.Maven, "org.example:property", []string{"1.0.0", "1.0.1"})
	addVersions(resolve.Maven, "org.example:same-property", []string{"1.0.0", "1.0.1"})
	addVersions(resolve.Maven, "org.example:another-property", []string{"1.0.0", "1.1.0"})
	addVersions(resolve.Maven, "org.example:property-no-update", []string{"1.9.0", "2.0.0"})
	addVersions(resolve.Maven, "org.example:xyz", []string{"2.0.0", "2.0.1"})
	addVersions(resolve.Maven, "org.profile:abc", []string{"1.2.3", "1.2.4"})
	addVersions(resolve.Maven, "org.profile:def", []string{"2.3.4", "2.3.5"})
	addVersions(resolve.Maven, "org.import:xyz", []string{"6.6.6", "6.7.0", "7.0.0"})
	addVersions(resolve.Maven, "org.dep:plugin-dep", []string{"2.3.1", "2.3.2", "2.3.3", "2.3.4"})

	suggester, err := NewSuggester(resolve.Maven)
	if err != nil {
		t.Fatalf("failed to get Maven suggester: %v", err)
	}

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	mf := testManifest{
		filePath: "pom.xml",
		root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "com.mycompany.app:my-app",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0.0",
			},
		},
		requirements: []resolve.RequirementVersion{
			{
				// Test dependencies are not updated.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "junit:junit",
					},
					VersionType: resolve.Requirement,
					Version:     "4.12",
				},
				Type: dep.NewType(dep.Test),
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:abc",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.1",
				},
			},
			{
				// A package is specified to disallow updates.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:no-updates",
					},
					VersionType: resolve.Requirement,
					Version:     "9.9.9",
				},
			},
			{
				// The universal property should be updated.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				// Property cannot be updated, so update the dependency directly.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:property-no-update",
					},
					VersionType: resolve.Requirement,
					Version:     "1.9",
				},
			},
			{
				// The property is updated to the same value.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:same-property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				// Property needs to be updated to a different value,
				// so update dependency directly.
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:another-property",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:xyz",
					},
					VersionType: resolve.Requirement,
					Version:     "2.0.0",
				},
				Type: depMgmt,
			},
		},
		groups: map[manifest.RequirementKey][]string{
			mavenReqKey(t, "junit:junit", "", ""):    {"test"},
			mavenReqKey(t, "org.import:xyz", "", ""): {"import"},
		},
		ecosystemSpecific: mavenmanifest.ManifestSpecific{
			RequirementsForUpdates: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "com.mycompany.app:parent-pom",
						},
						VersionType: resolve.Requirement,
						Version:     "1.0.0",
					},
					Type: depParent,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:abc",
						},
						VersionType: resolve.Requirement,
						Version:     "1.2.3",
					},
					Type: depProfileOne,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:def",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.4",
					},
					Type: depProfileOne,
				},
				{
					// A package is specified to ignore major updates.
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.import:xyz",
						},
						VersionType: resolve.Requirement,
						Version:     "6.6.6",
					},
					Type: depProfileTwoMgmt,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.dep:plugin-dep",
						},
						VersionType: resolve.Requirement,
						Version:     "2.3.3",
					},
					Type: depPlugin,
				},
			},
			OriginalRequirements: []mavenmanifest.DependencyWithOrigin{
				{
					Dependency: maven.Dependency{GroupID: "org.parent", ArtifactID: "parent-pom", Version: "1.2.0", Type: "pom"},
					Origin:     "parent",
				},
				{
					Dependency: maven.Dependency{GroupID: "junit", ArtifactID: "junit", Version: "${junit.version}", Scope: "test"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "abc", Version: "1.0.1"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "no-updates", Version: "9.9.9"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "no-version"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "property", Version: "${property.version}"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "property-no-update", Version: "1.${no.update.minor}"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "same-property", Version: "${property.version}"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "another-property", Version: "${property.version}"},
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "no-version", Version: "2.0.0"},
					Origin:     "management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.example", ArtifactID: "xyz", Version: "2.0.0"},
					Origin:     "management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "abc", Version: "1.2.3"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.profile", ArtifactID: "def", Version: "${def.version}"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.import", ArtifactID: "xyz", Version: "6.6.6", Scope: "import", Type: "pom"},
					Origin:     "profile@profile-two@management",
				},
				{
					Dependency: maven.Dependency{GroupID: "org.dep", ArtifactID: "plugin-dep", Version: "2.3.3"},
					Origin:     "plugin@org.plugin:plugin",
				},
			},
		},
	}

	got, err := suggester.Suggest(ctx, mf, options.UpdateOptions{
		ResolveClient: client,
		IgnoreDev:     true, // Do no update test dependencies.
		UpgradeConfig: upgrade.Config{
			"org.example:no-updates": upgrade.None,
			"org.import:xyz":         upgrade.Minor,
		},
	})
	if err != nil {
		t.Fatalf("failed to suggest Patch: %v", err)
	}

	want := result.Patch{
		PackageUpdates: []result.PackageUpdate{
			{
				Name:        "org.dep:plugin-dep",
				VersionFrom: "2.3.3",
				VersionTo:   "2.3.4",
				PURLFrom:    "pkg:maven/org.dep/plugin-dep@2.3.3",
				PURLTo:      "pkg:maven/org.dep/plugin-dep@2.3.4",
				Type:        depPlugin,
			},
			{
				Name:        "org.example:abc",
				VersionFrom: "1.0.1",
				VersionTo:   "1.0.2",
				PURLFrom:    "pkg:maven/org.example/abc@1.0.1",
				PURLTo:      "pkg:maven/org.example/abc@1.0.2",
			},
			{
				Name:        "org.example:another-property",
				VersionFrom: "1.0.0",
				VersionTo:   "1.1.0",
				PURLFrom:    "pkg:maven/org.example/another-property@1.0.0",
				PURLTo:      "pkg:maven/org.example/another-property@1.1.0",
			},
			{
				Name:        "org.example:property",
				VersionFrom: "1.0.0",
				VersionTo:   "1.0.1",
				PURLFrom:    "pkg:maven/org.example/property@1.0.0",
				PURLTo:      "pkg:maven/org.example/property@1.0.1",
			},
			{
				Name:        "org.example:property-no-update",
				VersionFrom: "1.9",
				VersionTo:   "2.0.0",
				PURLFrom:    "pkg:maven/org.example/property-no-update@1.9",
				PURLTo:      "pkg:maven/org.example/property-no-update@2.0.0",
			},
			{
				Name:        "org.example:same-property",
				VersionFrom: "1.0.0",
				VersionTo:   "1.0.1",
				PURLFrom:    "pkg:maven/org.example/same-property@1.0.0",
				PURLTo:      "pkg:maven/org.example/same-property@1.0.1",
			},
			{
				Name:        "org.example:xyz",
				VersionFrom: "2.0.0",
				VersionTo:   "2.0.1",
				PURLFrom:    "pkg:maven/org.example/xyz@2.0.0",
				PURLTo:      "pkg:maven/org.example/xyz@2.0.1",
				Type:        depMgmt,
			},
			{
				Name:        "org.import:xyz",
				VersionFrom: "6.6.6",
				VersionTo:   "6.7.0",
				PURLFrom:    "pkg:maven/org.import/xyz@6.6.6",
				PURLTo:      "pkg:maven/org.import/xyz@6.7.0",
				Type:        depProfileTwoMgmt,
			},
			{
				Name:        "org.profile:abc",
				VersionFrom: "1.2.3",
				VersionTo:   "1.2.4",
				PURLFrom:    "pkg:maven/org.profile/abc@1.2.3",
				PURLTo:      "pkg:maven/org.profile/abc@1.2.4",
				Type:        depProfileOne,
			},
			{
				Name:        "org.profile:def",
				VersionFrom: "2.3.4",
				VersionTo:   "2.3.5",
				PURLFrom:    "pkg:maven/org.profile/def@2.3.4",
				PURLTo:      "pkg:maven/org.profile/def@2.3.5",
				Type:        depProfileOne,
			},
		},
	}
	sort.Slice(got.PackageUpdates, func(i, j int) bool {
		return got.PackageUpdates[i].Name < got.PackageUpdates[j].Name
	})
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("Patch suggested does not match expected (-want +got): %s\n", diff)
	}
}

func Test_suggestMavenVersion(t *testing.T) {
	ctx := context.Background()
	lc := resolve.NewLocalClient()

	pk := resolve.PackageKey{
		System: resolve.Maven,
		Name:   "abc:xyz",
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0", "1.2.3", "2.0.0", "2.2.2", "2.3.4"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement string
		level       upgrade.Level
		want        string
	}{
		{"1.0.0", upgrade.Major, "2.3.4"},
		// No major updates allowed
		{"1.0.0", upgrade.Minor, "1.2.3"},
		// Only allow patch updates
		{"1.0.0", upgrade.Patch, "1.0.1"},
		// Version range requirement is not outdated
		{"[1.0.0,)", upgrade.Major, "[1.0.0,)"},
		{"[2.0.0,2.3.4]", upgrade.Major, "[2.0.0,2.3.4]"},
		// Version range requirement is outdated
		{"[2.0.0,2.3.4)", upgrade.Major, "2.3.4"},
		{"[2.0.0,2.2.2]", upgrade.Major, "2.3.4"},
		// Version range requirement is outdated but latest version is a major update
		{"[1.0.0,2.0.0)", upgrade.Major, "2.3.4"},
		{"[1.0.0,2.0.0)", upgrade.Minor, "[1.0.0,2.0.0)"},
	}
	for _, tt := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     tt.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     tt.want,
			},
		}
		got, err := suggestMavenVersion(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, tt.level)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggestMavenVersion(%v, %v): got %s want %s", vk, tt.level, got, want)
		}
	}
}

func TestSuggestVersion_Guava(t *testing.T) {
	ctx := context.Background()
	lc := resolve.NewLocalClient()

	pk := resolve.PackageKey{
		System: resolve.Maven,
		Name:   "com.google.guava:guava",
	}
	for _, version := range []string{"1.0.0", "1.0.1-android", "1.0.1-jre", "1.1.0-android", "1.1.0-jre", "2.0.0-android", "2.0.0-jre"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement string
		level       upgrade.Level
		want        string
	}{
		{"1.0.0", upgrade.Major, "2.0.0-jre"},
		// Update to the version with the same flavour
		{"1.0.1-jre", upgrade.Major, "2.0.0-jre"},
		{"1.0.1-android", upgrade.Major, "2.0.0-android"},
		{"1.0.1-jre", upgrade.Minor, "1.1.0-jre"},
		{"1.0.1-android", upgrade.Minor, "1.1.0-android"},
		// Version range requirement is not outdated
		{"[1.0.0,)", upgrade.Major, "[1.0.0,)"},
		// Version range requirement is outdated and the latest version is a major update
		{"[1.0.0,2.0.0)", upgrade.Major, "2.0.0-jre"},
		{"[1.0.0,2.0.0)", upgrade.Minor, "[1.0.0,2.0.0)"},
	}
	for _, tt := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     tt.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     tt.want,
			},
		}
		got, err := suggestMavenVersion(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, tt.level)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggestMavenVersion(%v, %v): got %s want %s", vk, tt.level, got, want)
		}
	}
}

func TestSuggestVersion_Commons(t *testing.T) {
	ctx := context.Background()
	lc := resolve.NewLocalClient()

	pk := resolve.PackageKey{
		System: resolve.Maven,
		Name:   "commons-io:commons-io",
	}
	for _, version := range []string{"1.0.0", "1.0.1", "1.1.0", "2.0.0", "20010101.000000"} {
		lc.AddVersion(resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Concrete,
				Version:     version,
			}}, nil)
	}

	tests := []struct {
		requirement string
		level       upgrade.Level
		want        string
	}{
		{"1.0.0", upgrade.Major, "2.0.0"},
		// No major updates allowed
		{"1.0.0", upgrade.Minor, "1.1.0"},
		// Only allow patch updates
		{"1.0.0", upgrade.Patch, "1.0.1"},
		// Version range requirement is not outdated
		{"[1.0.0,)", upgrade.Major, "[1.0.0,)"},
		// Version range requirement is outdated and the latest version is a major update
		{"[1.0.0,2.0.0)", upgrade.Major, "2.0.0"},
		{"[1.0.0,2.0.0)", upgrade.Minor, "[1.0.0,2.0.0)"},
	}
	for _, tt := range tests {
		vk := resolve.VersionKey{
			PackageKey:  pk,
			VersionType: resolve.Requirement,
			Version:     tt.requirement,
		}
		want := resolve.RequirementVersion{
			VersionKey: resolve.VersionKey{
				PackageKey:  pk,
				VersionType: resolve.Requirement,
				Version:     tt.want,
			},
		}
		got, err := suggestMavenVersion(ctx, lc, resolve.RequirementVersion{VersionKey: vk}, tt.level)
		if err != nil {
			t.Fatalf("fail to suggest a new version for %v: %v", vk, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("suggestMavenVersion(%v, %v): got %s want %s", vk, tt.level, got, want)
		}
	}
}
