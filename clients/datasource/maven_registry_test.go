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

package datasource_test

import (
	"context"
	"encoding/base64"
	"fmt"
	"reflect"
	"testing"
	"unsafe"

	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
)

func TestGetProject(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}, "")
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", got, want)
	}
}

func TestGetProjectSnapshot(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: srv.URL, SnapshotsEnabled: true}, "")
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	  <snapshot>
	    <timestamp>20230302.052731</timestamp>
	    <buildNumber>9</buildNumber>
	  </snapshot>
	  <lastUpdated>20230302052731</lastUpdated>
	  <snapshotVersions>
	    <snapshotVersion>
	      <extension>jar</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	    <snapshotVersion>
	      <extension>pom</extension>
	      <value>3.3.1-20230302.052731-9</value>
	      <updated>20230302052731</updated>
	    </snapshotVersion>
	  </snapshotVersions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/3.3.1-SNAPSHOT/x.y.z-3.3.1-20230302.052731-9.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.3.1-SNAPSHOT</version>
	</project>
	`))

	got, err := client.GetProject(context.Background(), "org.example", "x.y.z", "3.3.1-SNAPSHOT")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "3.3.1-SNAPSHOT", err)
	}
	want := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "3.3.1-SNAPSHOT",
		},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "3.3.1-SNAPSHOT", got, want)
	}
}

func TestMultipleRegistry(t *testing.T) {
	dft := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: dft.URL, ReleasesEnabled: true}, "")
	dft.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>3.0.0</latest>
	    <release>3.0.0</release>
	    <versions>
	      <version>2.0.0</version>
		    <version>3.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	dft.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))
	dft.SetResponse(t, "org/example/x.y.z/3.0.0/x.y.z-3.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>3.0.0</version>
	</project>
	`))

	srv := clienttest.NewMockHTTPServer(t)
	if err := client.AddRegistry(datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}); err != nil {
		t.Fatalf("failed to add registry %s: %v", srv.URL, err)
	}
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>2.0.0</latest>
	    <release>2.0.0</release>
	    <versions>
	      <version>1.0.0</version>
		    <version>2.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))
	srv.SetResponse(t, "org/example/x.y.z/2.0.0/x.y.z-2.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>2.0.0</version>
	</project>
	`))

	gotProj, err := client.GetProject(context.Background(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}
	wantProj := maven.Project{
		ProjectKey: maven.ProjectKey{
			GroupID:    "org.example",
			ArtifactID: "x.y.z",
			Version:    "1.0.0",
		},
	}
	if !reflect.DeepEqual(gotProj, wantProj) {
		t.Errorf("GetProject(%s, %s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", "1.0.0", gotProj, wantProj)
	}

	gotVersions, err := client.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0", "2.0.0", "3.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}

func TestUpdateDefaultRegistry(t *testing.T) {
	dft := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: dft.URL, ReleasesEnabled: true}, "")
	dft.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>1.0.0</latest>
	    <release>1.0.0</release>
	    <versions>
	      <version>1.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))

	gotVersions, err := client.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}

	srv := clienttest.NewMockHTTPServer(t)
	if err := client.AddRegistry(datasource.MavenRegistry{URL: srv.URL, ID: "default", ReleasesEnabled: true}); err != nil {
		t.Fatalf("failed to add registry %s: %v", srv.URL, err)
	}
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>2.0.0</latest>
	    <release>2.0.0</release>
	    <versions>
	      <version>2.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))

	gotVersions, err = client.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions = []maven.String{"2.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}

func TestWithoutRegistriesMaintainsAuthData(t *testing.T) {
	// Create mock server to test auth is maintained
	srv := clienttest.NewMockHTTPServer(t)

	// Create original client with multiple registries
	client, _ := datasource.NewMavenRegistryAPIClient(datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}, "")
	testRegistry1 := datasource.MavenRegistry{
		URL:             "https://test1.maven.org/maven2/",
		ID:              "test1",
		ReleasesEnabled: true,
	}
	testRegistry2 := datasource.MavenRegistry{
		URL:              "https://test2.maven.org/maven2/",
		ID:               "test2",
		SnapshotsEnabled: true,
	}
	if err := client.AddRegistry(testRegistry1); err != nil {
		t.Fatalf("failed to add registry %s: %v", testRegistry1.URL, err)
	}
	if err := client.AddRegistry(testRegistry2); err != nil {
		t.Fatalf("failed to add registry %s: %v", testRegistry2.URL, err)
	}

	// Override the ParseMavenSettings function
	testUsername := "testuser"
	testPassword := "testpass"

	// Directly modify registryAuths field in client via reflection
	rv := reflect.ValueOf(client).Elem()
	rf := rv.FieldByName("registryAuths")
	mockAuths := map[string]*datasource.HTTPAuthentication{
		"default": {
			SupportedMethods: []datasource.HTTPAuthMethod{datasource.AuthBasic},
			AlwaysAuth:       true,
			Username:         testUsername,
			Password:         testPassword,
		},
	}
	reflect.NewAt(rf.Type(), unsafe.Pointer(rf.UnsafeAddr())).Elem().Set(reflect.ValueOf(mockAuths))

	// Require test http client to always expect auth
	credentials := fmt.Sprintf("%s:%s", testUsername, testPassword)
	encodedCredentials := base64.StdEncoding.EncodeToString([]byte(credentials))
	srv.SetAuthorization(t, "Basic "+encodedCredentials)

	// Set up response that requires authentication
	srv.SetResponse(t, "org/example/x.y.z/maven-metadata.xml", []byte(`
	<metadata>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <versioning>
	    <latest>2.0.0</latest>
	    <release>2.0.0</release>
	    <versions>
	      <version>2.0.0</version>
	    </versions>
	  </versioning>
	</metadata>
	`))

	// Create client without registries
	clientWithoutReg := client.WithoutRegistries()

	// Verify registries are empty
	gotRegistries := clientWithoutReg.GetRegistries()
	if len(gotRegistries) != 0 {
		t.Errorf("WithoutRegistries() returned client with %d registries, want 0", len(gotRegistries))
	}

	// Test that authenticated calls still work with default registry
	GetVersions, err := clientWithoutReg.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}

	if len(GetVersions) != 1 {
		t.Errorf("WithoutRegistries() returned client with %d versions, want 1", len(GetVersions))
	}

}
