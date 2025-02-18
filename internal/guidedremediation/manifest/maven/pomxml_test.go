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

package maven_test

import (
	"testing"

	mavenutil "deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest"
	"github.com/google/osv-scalibr/internal/guidedremediation/manifest/maven"
)

var (
	depMgmt   = depTypeWithOrigin("management")
	depParent = depTypeWithOrigin("parent")
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

	return maven.MakeRequirementKey(resolve.RequirementVersion{
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
	FilePath          string
	Root              resolve.Version
	System            resolve.System
	Requirements      []resolve.RequirementVersion
	Groups            map[manifest.RequirementKey][]string
	EcosystemSpecific maven.ManifestSpecific
}

func checkManifest(t *testing.T, name string, got manifest.Manifest, want testManifest) {
	t.Helper()
	if want.FilePath != got.FilePath() {
		t.Errorf("%s.FilePath() = %q, want %q", name, got.FilePath(), want.FilePath)
	}
	if diff := cmp.Diff(want.Root, got.Root()); diff != "" {
		t.Errorf("%s.Root() (-want +got):\n%s", name, diff)
	}
	if want.System != got.System() {
		t.Errorf("%s.System() = %v, want %v", name, got.System(), want.System)
	}
	if diff := cmp.Diff(want.Requirements, got.Requirements()); diff != "" {
		t.Errorf("%s.Requirements() (-want +got):\n%s", name, diff)
	}
	if diff := cmp.Diff(want.Groups, got.Groups()); diff != "" {
		t.Errorf("%s.Groups() (-want +got):\n%s", name, diff)
	}
	if diff := cmp.Diff(want.EcosystemSpecific, got.EcosystemSpecific()); diff != "" {
		t.Errorf("%s.EcosystemSpecific() (-want +got):\n%s", name, diff)
	}
}

func TestRead(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	srv.SetResponse(t, "org/upstream/parent-pom/1.2.3/parent-pom-1.2.3.pom", []byte(`
<project>
	<groupId>org.upstream</groupId>
	<artifactId>parent-pom</artifactId>
	<version>1.2.3</version>
	<packaging>pom</packaging>
	<properties>
		<bbb.artifact>bbb</bbb.artifact>
		<bbb.version>2.2.2</bbb.version>
	</properties>
	<dependencyManagement>
	<dependencies>
		<dependency>
		<groupId>org.example</groupId>
		<artifactId>${bbb.artifact}</artifactId>
		<version>${bbb.version}</version>
		</dependency>
	</dependencies>
	</dependencyManagement>
</project>
`))
	srv.SetResponse(t, "org/import/import/1.0.0/import-1.0.0.pom", []byte(`
<project>
	<groupId>org.import</groupId>
	<artifactId>import</artifactId>
	<version>1.0.0</version>
	<packaging>pom</packaging>
	<properties>
		<ccc.version>3.3.3</ccc.version>
	</properties>
	<dependencyManagement>
		<dependencies>
			<dependency>
				<groupId>org.example</groupId>
				<artifactId>ccc</artifactId>
				<version>${ccc.version}</version>
			</dependency>
		</dependencies>
	</dependencyManagement>
</project>
`))

	fsys := scalibrfs.DirFS("./testdata")
	mavenRW, err := maven.GetReadWriter(srv.URL)
	if err != nil {
		t.Fatalf("error creating ReadWriter: %v", err)
	}

	got, err := mavenRW.Read("my-app/pom.xml", fsys)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	depType := depMgmt.Clone()
	depType.AddAttr(dep.MavenArtifactType, "pom")
	depType.AddAttr(dep.Scope, "import")

	depParent.AddAttr(dep.MavenArtifactType, "pom")

	var depExclusions dep.Type
	depExclusions.AddAttr(dep.MavenExclusions, "org.exclude:exclude")

	want := testManifest{
		FilePath: "my-app/pom.xml",
		Root: resolve.Version{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "com.mycompany.app:my-app",
				},
				VersionType: resolve.Concrete,
				Version:     "1.0",
			},
		},
		System: resolve.Maven,
		Requirements: []resolve.RequirementVersion{
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "junit:junit",
					},
					VersionType: resolve.Requirement,
					Version:     "4.12",
				},
				// Type: dep.NewType(dep.Test), test scope is ignored to make resolution work.
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
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:no-version",
					},
					VersionType: resolve.Requirement,
					Version:     "2.0.0",
				},
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:exclusions",
					},
					VersionType: resolve.Requirement,
					Version:     "1.0.0",
				},
				Type: depExclusions,
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
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:ddd",
					},
					VersionType: resolve.Requirement,
					Version:     "1.2.3",
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
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:no-version",
					},
					VersionType: resolve.Requirement,
					Version:     "2.0.0",
				},
				Type: depMgmt,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:aaa",
					},
					VersionType: resolve.Requirement,
					Version:     "1.1.1",
				},
				Type: depMgmt,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:bbb",
					},
					VersionType: resolve.Requirement,
					Version:     "2.2.2",
				},
				Type: depMgmt,
			},
			{
				VersionKey: resolve.VersionKey{
					PackageKey: resolve.PackageKey{
						System: resolve.Maven,
						Name:   "org.example:ccc",
					},
					VersionType: resolve.Requirement,
					Version:     "3.3.3",
				},
				Type: depMgmt,
			},
		},
		Groups: map[manifest.RequirementKey][]string{
			mavenReqKey(t, "junit:junit", "", ""):       {"test"},
			mavenReqKey(t, "org.import:xyz", "pom", ""): {"import"},
		},
		EcosystemSpecific: maven.ManifestSpecific{
			Parent: mavenutil.Parent{
				ProjectKey: mavenutil.ProjectKey{
					GroupID:    "org.parent",
					ArtifactID: "parent-pom",
					Version:    "1.1.1",
				},
				RelativePath: "../parent/pom.xml",
			},
			Properties: []maven.PropertyWithOrigin{
				{Property: mavenutil.Property{Name: "project.build.sourceEncoding", Value: "UTF-8"}},
				{Property: mavenutil.Property{Name: "maven.compiler.source", Value: "1.7"}},
				{Property: mavenutil.Property{Name: "maven.compiler.target", Value: "1.7"}},
				{Property: mavenutil.Property{Name: "junit.version", Value: "4.12"}},
				{Property: mavenutil.Property{Name: "zeppelin.daemon.package.base", Value: "../bin"}},
				{Property: mavenutil.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			},
			OriginalRequirements: []maven.DependencyWithOrigin{
				{
					Dependency: mavenutil.Dependency{GroupID: "org.parent", ArtifactID: "parent-pom", Version: "1.1.1", Type: "pom"},
					Origin:     "parent",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "junit", ArtifactID: "junit", Version: "${junit.version}", Scope: "test"},
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "abc", Version: "1.0.1"},
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "no-version"},
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "exclusions", Version: "1.0.0",
						Exclusions: []mavenutil.Exclusion{
							{GroupID: "org.exclude", ArtifactID: "exclude"},
						}},
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "xyz", Version: "2.0.0"},
					Origin:     "management",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "no-version", Version: "2.0.0"},
					Origin:     "management",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.import", ArtifactID: "import", Version: "1.0.0", Scope: "import", Type: "pom"},
					Origin:     "management",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.profile", ArtifactID: "abc", Version: "1.2.3"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.profile", ArtifactID: "def", Version: "${def.version}"},
					Origin:     "profile@profile-one",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.import", ArtifactID: "xyz", Version: "6.6.6", Scope: "import", Type: "pom"},
					Origin:     "profile@profile-two@management",
				},
				{
					Dependency: mavenutil.Dependency{GroupID: "org.dep", ArtifactID: "plugin-dep", Version: "2.3.3"},
					Origin:     "plugin@org.plugin:plugin",
				},
			},
			RequirementsForUpdates: []resolve.RequirementVersion{
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.parent:parent-pom",
						},
						VersionType: resolve.Requirement,
						Version:     "1.1.1",
					},
					Type: depParent,
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.import:import",
						},
						VersionType: resolve.Requirement,
						Version:     "1.0.0",
					},
					Type: depType,
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
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.profile:def",
						},
						VersionType: resolve.Requirement,
						Version:     "${def.version}",
					},
				},
				{
					VersionKey: resolve.VersionKey{
						PackageKey: resolve.PackageKey{
							System: resolve.Maven,
							Name:   "org.import:xyz",
						},
						VersionType: resolve.Requirement,
						Version:     "6.6.6",
					},
					Type: depType,
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
				},
			},
		},
	}

	checkManifest(t, "Manifest", got, want)
}
