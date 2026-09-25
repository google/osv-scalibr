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

package resolution_test

import (
	"os"
	"path/filepath"
	"testing"

	"deps.dev/util/resolve"
	"deps.dev/util/resolve/dep"
	"deps.dev/util/resolve/version"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/resolution"
)

func TestMavenRegistryClientCache(t *testing.T) {
	tempDir := t.TempDir()
	srv := clienttest.NewMockHTTPServer(t)

	parentPath := "org/example/parent/1.0.0/parent-1.0.0.pom"
	bomPath := "org/example/bom/1.0.0/bom-1.0.0.pom"
	appPath := "org/example/app/1.0.0/app-1.0.0.pom"

	srv.SetResponse(t, parentPath, []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>parent</artifactId>
	  <version>1.0.0</version>
	  <packaging>pom</packaging>
	  <dependencyManagement>
	    <dependencies>
	      <dependency>
	        <groupId>org.example</groupId>
	        <artifactId>bom</artifactId>
	        <version>1.0.0</version>
	        <type>pom</type>
	        <scope>import</scope>
	      </dependency>
	    </dependencies>
	  </dependencyManagement>
	</project>`))

	srv.SetResponse(t, bomPath, []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>bom</artifactId>
	  <version>1.0.0</version>
	  <packaging>pom</packaging>
	  <dependencyManagement>
	    <dependencies>
	      <dependency>
	        <groupId>org.dep</groupId>
	        <artifactId>managed-lib</artifactId>
	        <version>2.5.0</version>
	      </dependency>
	    </dependencies>
	  </dependencyManagement>
	</project>`))

	srv.SetResponse(t, appPath, []byte(`
	<project>
	  <parent>
	    <groupId>org.example</groupId>
	    <artifactId>parent</artifactId>
	    <version>1.0.0</version>
	  </parent>
	  <groupId>org.example</groupId>
	  <artifactId>app</artifactId>
	  <version>1.0.0</version>
	  <repositories>
	    <repository>
	      <id>custom</id>
	      <url>https://repo.example.com/maven2</url>
	    </repository>
	  </repositories>
	  <dependencies>
	    <dependency>
	      <groupId>org.dep</groupId>
	      <artifactId>managed-lib</artifactId>
	    </dependency>
	  </dependencies>
	</project>`))

	client, err := resolution.NewMavenRegistryClient(t.Context(), srv.URL, tempDir, false, srv.Client(), nil)
	if err != nil {
		t.Fatalf("NewMavenRegistryClient failed: %v", err)
	}

	vk := resolve.VersionKey{
		PackageKey: resolve.PackageKey{
			System: resolve.Maven,
			Name:   "org.example:app",
		},
		VersionType: resolve.Concrete,
		Version:     "1.0.0",
	}

	// 1. Verify Version() caching and AttrSet clone isolation.
	ver1, err := client.Version(t.Context(), vk)
	if err != nil {
		t.Fatalf("first Version() failed: %v", err)
	}
	var wantAttr version.AttrSet
	wantAttr.SetAttr(version.Registries, "dep:https://repo.example.com/maven2")
	wantVer := resolve.Version{VersionKey: vk, AttrSet: wantAttr}
	if diff := cmp.Diff(wantVer, ver1); diff != "" {
		t.Fatalf("Version() diff (-want +got):\n%s", diff)
	}

	// Mutate ver1's AttrSet to verify clone isolation.
	ver1.SetAttr(version.Registries, "mutated")

	// 2. Verify Requirements() resolves parent + BOM and caches the resulting requirements.
	reqs1, err := client.Requirements(t.Context(), vk)
	if err != nil {
		t.Fatalf("first Requirements() failed: %v", err)
	}
	wantReqs := []resolve.RequirementVersion{
		{
			VersionKey: resolve.VersionKey{
				PackageKey: resolve.PackageKey{
					System: resolve.Maven,
					Name:   "org.dep:managed-lib",
				},
				VersionType: resolve.Requirement,
				Version:     "2.5.0",
			},
			Type: dep.NewType(),
		},
	}
	if diff := cmp.Diff(wantReqs, reqs1); diff != "" {
		t.Fatalf("Requirements() diff (-want +got):\n%s", diff)
	}

	// Mutate reqs1 in place to verify clone isolation.
	reqs1[0].Version = "mutated"
	reqs1[0].Type.AddAttr(dep.Scope, "test")

	// Corrupt all on-disk cached POM files to verify subsequent Version() and Requirements()
	// calls are served from the in-memory caches without touching disk or network.
	for _, p := range []string{parentPath, bomPath, appPath} {
		diskFile := filepath.Join(tempDir, "maven", p)
		if err := os.WriteFile(diskFile, []byte("corrupted xml"), 0666); err != nil {
			t.Fatalf("failed to overwrite disk cache file %s: %v", diskFile, err)
		}
	}

	ver2, err := client.Version(t.Context(), vk)
	if err != nil {
		t.Fatalf("second Version() failed: %v", err)
	}
	if diff := cmp.Diff(wantVer, ver2); diff != "" {
		t.Errorf("cached Version() diff (-want +got):\n%s", diff)
	}

	reqs2, err := client.Requirements(t.Context(), vk)
	if err != nil {
		t.Fatalf("second Requirements() failed: %v", err)
	}
	if diff := cmp.Diff(wantReqs, reqs2); diff != "" {
		t.Errorf("cached Requirements() diff (-want +got):\n%s", diff)
	}
}
