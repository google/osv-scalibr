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

package mavenutil

import (
	"bytes"
	"io"
	"net/http"
	"path/filepath"
	"reflect"
	"testing"

	"deps.dev/util/maven"
	"deps.dev/util/resolve"
	"deps.dev/util/semver"
	"github.com/google/osv-scalibr/clients/datasource"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/testing/extracttest"
	"github.com/google/osv-scalibr/testing/fakefs"
)

func TestParentPOMPath(t *testing.T) {
	input := extracttest.GenerateScanInputMock(t, extracttest.ScanInputMockConfig{
		Path: filepath.Join("testdata", "my-app", "pom.xml"),
	})
	defer extracttest.CloseTestScanInput(t, input)

	tests := []struct {
		currentPath, relativePath string
		want                      string
	}{
		// testdata
		// |- maven
		// |  |- my-app
		// |  |  |- pom.xml
		// |  |- parent
		// |  |  |- pom.xml
		// |- pom.xml
		{
			// Parent path is specified correctly.
			currentPath:  filepath.Join("testdata", "my-app", "pom.xml"),
			relativePath: "../parent/pom.xml",
			want:         filepath.Join("testdata", "parent", "pom.xml"),
		},
		{
			// Wrong file name is specified in relative path.
			currentPath:  filepath.Join("testdata", "my-app", "pom.xml"),
			relativePath: "../parent/abc.xml",
			want:         "",
		},
		{
			// Wrong directory is specified in relative path.
			currentPath:  filepath.Join("testdata", "my-app", "pom.xml"),
			relativePath: "../not-found/pom.xml",
			want:         "",
		},
		{
			// Only directory is specified.
			currentPath:  filepath.Join("testdata", "my-app", "pom.xml"),
			relativePath: "../parent",
			want:         filepath.Join("testdata", "parent", "pom.xml"),
		},
		{
			// Parent relative path is default to '../pom.xml'.
			currentPath:  filepath.Join("testdata", "my-app", "pom.xml"),
			relativePath: "",
			want:         filepath.Join("testdata", "pom.xml"),
		},
		{
			// No pom.xml is found even in the default path.
			currentPath:  filepath.Join("testdata", "pom.xml"),
			relativePath: "",
			want:         "",
		},
	}
	for _, tt := range tests {
		got := ParentPOMPath(&input, tt.currentPath, tt.relativePath)
		if got != filepath.ToSlash(tt.want) {
			t.Errorf("ParentPOMPath(%s, %s): got %s, want %s", tt.currentPath, tt.relativePath, got, tt.want)
		}
	}
}

func TestCompareVersions(t *testing.T) {
	versionKey := func(name string, version string) resolve.VersionKey {
		return resolve.VersionKey{
			PackageKey: resolve.PackageKey{
				System: resolve.Maven,
				Name:   name,
			},
			Version: version,
		}
	}
	semVer := func(version string) *semver.Version {
		parsed, _ := resolve.Maven.Semver().Parse(version)
		return parsed
	}

	tests := []struct {
		vk   resolve.VersionKey
		a, b *semver.Version
		want int
	}{
		{
			versionKey("abc:xyz", "1.0.0"),
			semVer("1.2.3"),
			semVer("1.2.3"),
			0,
		},
		{
			versionKey("abc:xyz", "1.0.0"),
			semVer("1.2.3"),
			semVer("2.3.4"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0"),
			semVer("1.2.3"),
			semVer("2.3.4"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0"),
			semVer("1.2.3-jre"),
			semVer("2.3.4-jre"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0"),
			semVer("1.2.3-android"),
			semVer("2.3.4-android"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0"),
			semVer("2.3.4-android"),
			semVer("1.2.3-jre"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0-jre"),
			semVer("1.2.3-android"),
			semVer("1.2.3-jre"),
			-1,
		},
		{
			versionKey("com.google.guava:guava", "1.0.0-android"),
			semVer("1.2.3-android"),
			semVer("1.2.3-jre"),
			1,
		},
		{
			versionKey("commons-io:commons-io", "1.0.0"),
			semVer("1.2.3"),
			semVer("2.3.4"),
			-1,
		},
		{
			versionKey("commons-io:commons-io", "1.0.0"),
			semVer("1.2.3"),
			semVer("20010101.000000"),
			1,
		},
	}
	for _, tt := range tests {
		got := CompareVersions(tt.vk, tt.a, tt.b)
		if got != tt.want {
			t.Errorf("CompareVersions(%v, %v, %v): got %b, want %b", tt.vk, tt.a, tt.b, got, tt.want)
		}
	}
}

func TestDiscoverModules(t *testing.T) {
	txt := `
-- pom.xml --
<project>
  <groupId>org.example</groupId>
  <artifactId>parent-project</artifactId>
  <version>1.0.0</version>
  <packaging>pom</packaging>
  <modules>
    <module>sub-dir</module>
    <module>sub-file.xml</module>
  </modules>
</project>
-- sub-dir/pom.xml --
<project>
  <groupId>org.example</groupId>
  <artifactId>sub-dir-module</artifactId>
  <version>1.0.0</version>
</project>
-- sub-file.xml --
<project>
  <groupId>org.example</groupId>
  <artifactId>sub-file-module</artifactId>
  <version>1.0.0</version>
</project>
`
	fsys, err := fakefs.PrepareFS(txt)
	if err != nil {
		t.Fatalf("failed to prepare fake fs: %v", err)
	}

	client, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "")
	if err != nil {
		t.Fatalf("failed to create maven registry client: %v", err)
	}

	scanRoot := &scalibrfs.ScanRoot{FS: fsys, Path: ""}
	DiscoverModules(scanRoot, []string{"pom.xml"}, client)

	tests := []struct {
		g, a, v string
	}{
		{g: "org.example", a: "parent-project", v: "1.0.0"},
		{g: "org.example", a: "sub-dir-module", v: "1.0.0"},
		{g: "org.example", a: "sub-file-module", v: "1.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.a, func(t *testing.T) {
			_, err := client.GetProject(t.Context(), tt.g, tt.a, tt.v)
			if err != nil {
				t.Errorf("failed to get project %s:%s:%s from local registry: %v", tt.g, tt.a, tt.v, err)
			}
		})
	}
}

type countingTransport struct {
	calls int
	body  []byte
}

func (c *countingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	c.calls++
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader(c.body)),
	}, nil
}

func TestGetDependencyManagementCache(t *testing.T) {
	transport := &countingTransport{
		body: []byte(`
		<project>
		  <groupId>org.example</groupId>
		  <artifactId>bom</artifactId>
		  <version>1.0.0</version>
		  <packaging>pom</packaging>
		  <properties>
		    <lib.version>2.3.4</lib.version>
		  </properties>
		  <dependencyManagement>
		    <dependencies>
		      <dependency>
		        <groupId>org.dep</groupId>
		        <artifactId>lib</artifactId>
		        <version>${lib.version}</version>
		      </dependency>
		    </dependencies>
		  </dependencyManagement>
		</project>`),
	}
	client, err := datasource.NewMavenRegistryAPIClient(
		t.Context(),
		datasource.MavenRegistry{URL: "https://example.com/maven2", ReleasesEnabled: true},
		"",
		false,
		&http.Client{Transport: transport},
		nil,
	)
	if err != nil {
		t.Fatalf("failed to create maven registry client: %v", err)
	}

	dm1, err := GetDependencyManagement(t.Context(), client, "org.example", "bom", "1.0.0")
	if err != nil {
		t.Fatalf("first GetDependencyManagement failed: %v", err)
	}
	want := maven.DependencyManagement{
		Dependencies: []maven.Dependency{
			{
				GroupID:    "org.dep",
				ArtifactID: "lib",
				Version:    "2.3.4",
			},
		},
	}
	if !reflect.DeepEqual(dm1, want) {
		t.Fatalf("GetDependencyManagement() = %v, want %v", dm1, want)
	}
	if transport.calls != 1 {
		t.Fatalf("transport.calls = %d, want 1", transport.calls)
	}

	// Mutate dm1 to verify the cached DependencyManagement is isolated.
	dm1.Dependencies[0].Version = "mutated"

	dm2, err := GetDependencyManagement(t.Context(), client.WithoutRegistries(), "org.example", "bom", "1.0.0")
	if err != nil {
		t.Fatalf("second GetDependencyManagement failed: %v", err)
	}
	if !reflect.DeepEqual(dm2, want) {
		t.Errorf("second GetDependencyManagement() = %v, want %v", dm2, want)
	}
	if transport.calls != 1 {
		t.Errorf("transport.calls = %d after cached call, want 1", transport.calls)
	}
}
