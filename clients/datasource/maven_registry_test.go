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

package datasource_test

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"deps.dev/util/maven"
	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
)

func TestGetProject(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	got, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
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
	client, _ := datasource.NewMavenRegistryAPIClient(t.Context(), datasource.MavenRegistry{URL: srv.URL, SnapshotsEnabled: true}, "", false, &http.Client{}, nil)
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

	got, err := client.GetProject(t.Context(), "org.example", "x.y.z", "3.3.1-SNAPSHOT")
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
	// AddRegistry rejects loopback URLs by default, so pretend the mock
	// server's 127.0.0.1 address resolves to a public address for the
	// duration of this test.
	t.Cleanup(datasource.SetLookupHostForTest(func(string) ([]string, error) {
		return []string{"203.0.113.1"}, nil
	}))
	dft := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), dft.URL)
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
	if err := client.AddRegistry(t.Context(), datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}); err != nil {
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

	gotProj, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
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

	gotVersions, err := client.GetVersions(t.Context(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0", "2.0.0", "3.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}

func TestUpdateDefaultRegistry(t *testing.T) {
	// AddRegistry rejects loopback URLs by default, so pretend the mock
	// server's 127.0.0.1 address resolves to a public address for the
	// duration of this test.
	t.Cleanup(datasource.SetLookupHostForTest(func(string) ([]string, error) {
		return []string{"203.0.113.1"}, nil
	}))
	dft := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), dft.URL)
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

	gotVersions, err := client.GetVersions(t.Context(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions := []maven.String{"1.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}

	srv := clienttest.NewMockHTTPServer(t)
	if err := client.AddRegistry(t.Context(), datasource.MavenRegistry{URL: srv.URL, ID: "default", ReleasesEnabled: true}); err != nil {
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

	gotVersions, err = client.GetVersions(t.Context(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}
	wantVersions = []maven.String{"2.0.0"}
	if !reflect.DeepEqual(gotVersions, wantVersions) {
		t.Errorf("GetVersions(%s, %s):\ngot %v\nwant %v\n", "org.example", "x.y.z", gotVersions, wantVersions)
	}
}

func TestMavenLocalRegistry(t *testing.T) {
	tempDir := t.TempDir()
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := datasource.NewMavenRegistryAPIClient(t.Context(), datasource.MavenRegistry{URL: srv.URL, ReleasesEnabled: true}, tempDir, false, &http.Client{}, nil)
	path := "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom"
	resp := []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>`)
	srv.SetResponse(t, path, resp)

	_, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("failed to get Maven project %s:%s verion %s: %v", "org.example", "x.y.z", "1.0.0", err)
	}

	// Check that the pom file is stored locally.
	filePath := filepath.Join(tempDir, "maven", path)
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("failed to read file: %v", err)
	}
	if !bytes.Equal(content, resp) {
		t.Errorf("unexpected file content: got %s, want %s", string(content), string(resp))
	}
}

type trackingTransport struct {
	mu     sync.Mutex
	called bool
}

func (t *trackingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.mu.Lock()
	t.called = true
	t.mu.Unlock()
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(bytes.NewReader([]byte("<project><groupId>g</groupId><artifactId>a</artifactId><version>v</version></project>"))),
	}, nil
}

func (t *trackingTransport) wasCalled() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.called
}

// TestDisableGoogleAuthRespected tests that setting disableGoogleAuth = true in
// NewMavenRegistryAPIClient prevents the Google client from being used for
// Artifact Registry requests, falling back to the standard HTTP client.
func TestDisableGoogleAuthRespected(t *testing.T) {
	standardTransport := &trackingTransport{}
	googleTransport := &trackingTransport{}

	standardClient := &http.Client{Transport: standardTransport}
	googleClient := &http.Client{Transport: googleTransport}

	client, err := datasource.NewMavenRegistryAPIClient(
		t.Context(),
		datasource.MavenRegistry{URL: "artifactregistry://example.com", ReleasesEnabled: true},
		"",   // localRegistry
		true, // disableGoogleAuth
		standardClient,
		googleClient,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
	}

	_, _ = client.GetProject(t.Context(), "g", "a", "v")

	if googleTransport.wasCalled() {
		t.Errorf("Google client was called when disableGoogleAuth is true")
	}
	if !standardTransport.wasCalled() {
		t.Errorf("Standard client was not called")
	}
}

// TestDisableGoogleAuthMethodRespected tests that dynamically calling
// DisableGoogleAuth() post-construction prevents the Google client from being
// used for Artifact Registry requests.
func TestDisableGoogleAuthMethodRespected(t *testing.T) {
	standardTransport := &trackingTransport{}
	googleTransport := &trackingTransport{}

	standardClient := &http.Client{Transport: standardTransport}
	googleClient := &http.Client{Transport: googleTransport}

	client, err := datasource.NewMavenRegistryAPIClient(
		t.Context(),
		datasource.MavenRegistry{URL: "artifactregistry://example.com", ReleasesEnabled: true},
		"",    // localRegistry
		false, // disableGoogleAuth
		standardClient,
		googleClient,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
	}

	client.DisableGoogleAuth()

	_, _ = client.GetProject(t.Context(), "g", "a", "v")

	if googleTransport.wasCalled() {
		t.Errorf("Google client was called after DisableGoogleAuth()")
	}
	if !standardTransport.wasCalled() {
		t.Errorf("Standard client was not called")
	}
}
