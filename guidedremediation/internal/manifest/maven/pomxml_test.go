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

package maven

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	mavenutil "deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/guidedremediation/internal/manifest"
	"github.com/google/osv-scalibr/guidedremediation/result"
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

	return MakeRequirementKey(resolve.RequirementVersion{
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
	EcosystemSpecific ManifestSpecific
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

func compareToFile(t *testing.T, got io.Reader, wantFile string) {
	t.Helper()
	wantBytes, err := os.ReadFile(wantFile)
	if err != nil {
		t.Fatalf("error reading %s: %v", wantFile, err)
	}
	gotBytes, err := io.ReadAll(got)
	if err != nil {
		t.Fatalf("error reading manifest: %v", err)
	}

	if runtime.GOOS == "windows" {
		// Go doesn't write CRLF in xml on Windows, trying to fix this is difficult.
		// Just ignore it in the tests.
		wantBytes = bytes.ReplaceAll(wantBytes, []byte("\r\n"), []byte("\n"))
		gotBytes = bytes.ReplaceAll(gotBytes, []byte("\r\n"), []byte("\n"))
	}

	if diff := cmp.Diff(wantBytes, gotBytes); diff != "" {
		t.Errorf("%s (-want +got):\n%s", wantFile, diff)
	}
}

func TestReadWrite(t *testing.T) {
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
	mavenRW, err := GetReadWriter(srv.URL)
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
		EcosystemSpecific: ManifestSpecific{
			Parent: mavenutil.Parent{
				ProjectKey: mavenutil.ProjectKey{
					GroupID:    "org.parent",
					ArtifactID: "parent-pom",
					Version:    "1.1.1",
				},
				RelativePath: "../parent/pom.xml",
			},
			Properties: []PropertyWithOrigin{
				{Property: mavenutil.Property{Name: "project.build.sourceEncoding", Value: "UTF-8"}},
				{Property: mavenutil.Property{Name: "maven.compiler.source", Value: "1.7"}},
				{Property: mavenutil.Property{Name: "maven.compiler.target", Value: "1.7"}},
				{Property: mavenutil.Property{Name: "junit.version", Value: "4.12"}},
				{Property: mavenutil.Property{Name: "zeppelin.daemon.package.base", Value: "../bin"}},
				{Property: mavenutil.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			},
			OriginalRequirements: []DependencyWithOrigin{
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

	// Test writing the files produces the same pom.xml files.
	dir := t.TempDir()
	if err := mavenRW.Write(got, fsys, nil, filepath.Join(dir, "my-app", "pom.xml")); err != nil {
		t.Fatalf("error writing manifest: %v", err)
	}

	gotFile, err := os.Open(filepath.Join(dir, "my-app", "pom.xml"))
	if err != nil {
		t.Fatalf("error opening pom.xml: %v", err)
	}
	defer gotFile.Close()
	compareToFile(t, gotFile, "testdata/my-app/pom.xml")

	gotFile, err = os.Open(filepath.Join(dir, "parent", "pom.xml"))
	if err != nil {
		t.Fatalf("error opening pom.xml: %v", err)
	}
	defer gotFile.Close()
	compareToFile(t, gotFile, "testdata/parent/pom.xml")

	gotFile, err = os.Open(filepath.Join(dir, "parent", "grandparent", "pom.xml"))
	if err != nil {
		t.Fatalf("error opening pom.xml: %v", err)
	}
	defer gotFile.Close()
	compareToFile(t, gotFile, "testdata/parent/grandparent/pom.xml")
}

func TestMavenWrite(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	in, err := os.ReadFile(filepath.Join(dir, "testdata", "my-app", "pom.xml"))
	if err != nil {
		t.Fatalf("fail to open file: %v", err)
	}

	patches := Patches{
		DependencyPatches: DependencyPatches{
			"": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.example",
						ArtifactID: "abc",
						Type:       "jar",
					},
					NewRequire: "1.0.2",
				}: true,
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.example",
						ArtifactID: "no-version",
						Type:       "jar",
					},
					NewRequire: "2.0.1",
				}: true,
			},
			"management": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.example",
						ArtifactID: "xyz",
						Type:       "jar",
					},
					NewRequire: "2.0.1",
				}: true,
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.example",
						ArtifactID: "extra-one",
						Type:       "jar",
					},
					NewRequire: "6.6.6",
				}: false,
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.example",
						ArtifactID: "extra-two",
						Type:       "jar",
					},
					NewRequire: "9.9.9",
				}: false,
			},
			"profile@profile-one": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.profile",
						ArtifactID: "abc",
						Type:       "jar",
					},
					NewRequire: "1.2.4",
				}: true,
			},
			"profile@profile-two@management": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.import",
						ArtifactID: "xyz",
						Type:       "pom",
					},
					NewRequire: "7.0.0",
				}: true,
			},
			"plugin@org.plugin:plugin": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.dep",
						ArtifactID: "plugin-dep",
						Type:       "jar",
					},
					NewRequire: "2.3.4",
				}: true,
			},
		},
		PropertyPatches: PropertyPatches{
			"": {
				"junit.version": "4.13.2",
			},
			"profile@profile-one": {
				"def.version": "2.3.5",
			},
		},
	}

	out := new(bytes.Buffer)
	if err := write(string(in), out, patches); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	compareToFile(t, out, filepath.Join(dir, "testdata", "my-app", "write_want.pom.xml"))
}

func TestMavenWriteDM(t *testing.T) {
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get current directory: %v", err)
	}
	in, err := os.ReadFile(filepath.Join(dir, "testdata", "no-dependency-management", "pom.xml"))
	if err != nil {
		t.Fatalf("fail to open file: %v", err)
	}

	patches := Patches{
		DependencyPatches: DependencyPatches{
			"": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "junit",
						ArtifactID: "junit",
						Type:       "jar",
					},
					NewRequire: "4.13.2",
				}: true,
			},
			"parent": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.parent",
						ArtifactID: "parent-pom",
						Type:       "jar",
					},
					NewRequire: "1.2.0",
				}: true,
			},
			"management": map[Patch]bool{
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.management",
						ArtifactID: "abc",
						Type:       "jar",
					},
					NewRequire: "1.2.3",
				}: false,
				{
					DependencyKey: mavenutil.DependencyKey{
						GroupID:    "org.management",
						ArtifactID: "xyz",
						Type:       "jar",
					},
					NewRequire: "2.3.4",
				}: false,
			},
		},
	}

	out := new(bytes.Buffer)
	if err := write(string(in), out, patches); err != nil {
		t.Fatalf("unable to update Maven pom.xml: %v", err)
	}
	compareToFile(t, out, filepath.Join(dir, "testdata", "no-dependency-management", "want.pom.xml"))
}

func Test_buildPatches(t *testing.T) {
	const parentPath = "testdata/parent/pom.xml"

	depProfileTwoMgmt.AddAttr(dep.MavenArtifactType, "pom")
	depProfileTwoMgmt.AddAttr(dep.Scope, "import")

	depParent.AddAttr(dep.MavenArtifactType, "pom")

	patches := []result.Patch{
		{
			PackageUpdates: []result.PackageUpdate{
				{
					Name:      "org.dep:plugin-dep",
					VersionTo: "2.3.4",
					Type:      depPlugin,
				},
				{
					Name:      "org.example:abc",
					VersionTo: "1.0.2",
				},
				{
					Name:      "org.example:aaa",
					VersionTo: "1.2.0",
				},
				{
					Name:      "org.example:ddd",
					VersionTo: "1.3.0",
				},
				{
					Name:      "org.example:property",
					VersionTo: "1.0.1",
				},
				{
					Name:      "org.example:same-property",
					VersionTo: "1.0.1",
				},
				{
					Name:      "org.example:another-property",
					VersionTo: "1.1.0",
				},
				{
					Name:      "org.example:property-no-update",
					VersionTo: "2.0.0",
				},
				{
					Name:      "org.example:xyz",
					VersionTo: "2.0.1",
					Type:      depMgmt,
				},
				{
					Name:      "org.import:xyz",
					VersionTo: "6.7.0",
					Type:      depProfileTwoMgmt,
				},
				{
					Name:      "org.profile:abc",
					VersionTo: "1.2.4",
					Type:      depProfileOne,
				},
				{
					Name:      "org.profile:def",
					VersionTo: "2.3.5",
					Type:      depProfileOne,
				},
				{
					Name:      "org.parent:parent-pom",
					VersionTo: "1.2.0",
					Type:      depParent,
				},
				{
					Name:        "org.example:suggest",
					VersionFrom: "1.0.0",
					VersionTo:   "2.0.0",
					Type:        depMgmt,
				},
				{
					Name:      "org.example:override",
					VersionTo: "2.0.0",
					Type:      depMgmt,
				},
				{
					Name:      "org.example:no-version",
					VersionTo: "2.0.1",
					Type:      depMgmt,
				},
			},
		},
	}
	specific := ManifestSpecific{
		Parent: mavenutil.Parent{
			ProjectKey: mavenutil.ProjectKey{
				GroupID:    "org.parent",
				ArtifactID: "parent-pom",
				Version:    "1.1.1",
			},
			RelativePath: "../parent/pom.xml",
		},
		Properties: []PropertyWithOrigin{
			{Property: mavenutil.Property{Name: "property.version", Value: "1.0.0"}},
			{Property: mavenutil.Property{Name: "no.update.minor", Value: "9"}},
			{Property: mavenutil.Property{Name: "def.version", Value: "2.3.4"}, Origin: "profile@profile-one"},
			{Property: mavenutil.Property{Name: "aaa.version", Value: "1.1.1"}, Origin: "parent@" + parentPath},
		},
		OriginalRequirements: []DependencyWithOrigin{
			{
				Dependency: mavenutil.Dependency{GroupID: "org.parent", ArtifactID: "parent-pom", Version: "1.2.0", Type: "pom"},
				Origin:     "parent",
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "junit", ArtifactID: "junit", Version: "${junit.version}", Scope: "test"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "abc", Version: "1.0.1"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "no-updates", Version: "9.9.9"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "no-version"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "property", Version: "${property.version}"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "property-no-update", Version: "1.${no.update.minor}"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "same-property", Version: "${property.version}"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "another-property", Version: "${property.version}"},
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "no-version", Version: "2.0.0"},
				Origin:     "management",
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "xyz", Version: "2.0.0"},
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
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "ddd", Version: "1.2.3"},
				Origin:     "parent@" + parentPath,
			},
			{
				Dependency: mavenutil.Dependency{GroupID: "org.example", ArtifactID: "aaa", Version: "${aaa.version}"},
				Origin:     "parent@" + parentPath + "@management",
			},
		},
	}
	want := map[string]Patches{
		"": {
			DependencyPatches: DependencyPatches{
				"": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "abc",
							Type:       "jar",
						},
						NewRequire: "1.0.2",
					}: true,
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "another-property",
							Type:       "jar",
						},
						NewRequire: "1.1.0",
					}: true,
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "property-no-update",
							Type:       "jar",
						},
						NewRequire: "2.0.0",
					}: true,
				},
				"management": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "xyz",
							Type:       "jar",
						},
						NewRequire: "2.0.1",
					}: true,
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "no-version",
							Type:       "jar",
						},
						NewRequire: "2.0.1",
					}: true,
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "override",
							Type:       "jar",
						},
						NewRequire: "2.0.0",
					}: false,
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "suggest",
							Type:       "jar",
						},
						NewRequire: "2.0.0",
					}: false,
				},
				"profile@profile-one": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.profile",
							ArtifactID: "abc",
							Type:       "jar",
						},
						NewRequire: "1.2.4",
					}: true,
				},
				"profile@profile-two@management": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.import",
							ArtifactID: "xyz",
							Type:       "pom",
						},
						NewRequire: "6.7.0",
					}: true,
				},
				"plugin@org.plugin:plugin": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.dep",
							ArtifactID: "plugin-dep",
							Type:       "jar",
						},
						NewRequire: "2.3.4",
					}: true,
				},
				"parent": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.parent",
							ArtifactID: "parent-pom",
							Type:       "pom",
						},
						NewRequire: "1.2.0",
					}: true,
				},
			},
			PropertyPatches: PropertyPatches{
				"": {
					"property.version": "1.0.1",
				},
				"profile@profile-one": {
					"def.version": "2.3.5",
				},
			},
		},
		parentPath: {
			DependencyPatches: DependencyPatches{
				"": map[Patch]bool{
					{
						DependencyKey: mavenutil.DependencyKey{
							GroupID:    "org.example",
							ArtifactID: "ddd",
							Type:       "jar",
						},
						NewRequire: "1.3.0",
					}: true,
				},
			},
			PropertyPatches: PropertyPatches{
				"": {
					"aaa.version": "1.2.0",
				},
			},
		},
	}

	allPatches, err := buildPatches(patches, specific)
	if err != nil {
		t.Fatalf("failed to build patches: %v", err)
	}
	if diff := cmp.Diff(want, allPatches); diff != "" {
		t.Errorf("result patches mismatch (-want +got):\n%s", diff)
	}
}

func Test_generatePropertyPatches(t *testing.T) {
	tests := []struct {
		s1       string
		s2       string
		possible bool
		patches  map[string]string
	}{
		{"${version}", "1.2.3", true, map[string]string{"version": "1.2.3"}},
		{"${major}.2.3", "1.2.3", true, map[string]string{"major": "1"}},
		{"1.${minor}.3", "1.2.3", true, map[string]string{"minor": "2"}},
		{"1.2.${patch}", "1.2.3", true, map[string]string{"patch": "3"}},
		{"${major}.${minor}.${patch}", "1.2.3", true, map[string]string{"major": "1", "minor": "2", "patch": "3"}},
		{"${major}.2.3", "2.0.0", false, map[string]string{}},
		{"1.${minor}.3", "2.0.0", false, map[string]string{}},
	}
	for _, tt := range tests {
		patches, ok := generatePropertyPatches(tt.s1, tt.s2)
		if ok != tt.possible || !reflect.DeepEqual(patches, tt.patches) {
			t.Errorf("generatePropertyPatches(%s, %s): got %v %v, want %v %v", tt.s1, tt.s2, patches, ok, tt.patches, tt.possible)
		}
	}
}
