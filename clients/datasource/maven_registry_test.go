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

func TestMavenLocalRegistryEscape(t *testing.T) {
	t.Run("path traversal", func(t *testing.T) {
		tempDir := t.TempDir()
		localRegistry := filepath.Join(tempDir, "cache")
		outsidePath := filepath.Join(tempDir, "outside", "maven-metadata.xml")
		if err := os.MkdirAll(filepath.Dir(outsidePath), 0755); err != nil {
			t.Fatalf("failed to create outside directory: %v", err)
		}

		transport := &trackingTransport{}
		client, err := datasource.NewMavenRegistryAPIClient(
			t.Context(),
			datasource.MavenRegistry{URL: "https://example.com", ReleasesEnabled: true},
			localRegistry,
			false,
			&http.Client{Transport: transport},
			nil,
		)
		if err != nil {
			t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
		}

		if _, err := client.GetVersions(t.Context(), "g", filepath.Join("..", "..", "..", "outside")); err != nil {
			t.Fatalf("GetVersions failed: %v", err)
		}
		if !transport.wasCalled() {
			t.Fatal("registry was not queried")
		}

		if _, err := os.Stat(outsidePath); !os.IsNotExist(err) {
			t.Errorf("outside file was created, os.Stat() returned %v", err)
		}
	})

	t.Run("symlink", func(t *testing.T) {
		tempDir := t.TempDir()
		localRegistry := filepath.Join(tempDir, "cache")
		cacheRoot := filepath.Join(localRegistry, "maven")
		outsideDir := filepath.Join(tempDir, "outside")
		if err := os.MkdirAll(cacheRoot, 0755); err != nil {
			t.Fatalf("failed to create cache directory: %v", err)
		}
		if err := os.MkdirAll(outsideDir, 0755); err != nil {
			t.Fatalf("failed to create outside directory: %v", err)
		}
		if err := os.Symlink(outsideDir, filepath.Join(cacheRoot, "g")); err != nil {
			t.Skipf("failed to create symlink: %v", err)
		}

		transport := &trackingTransport{}
		client, err := datasource.NewMavenRegistryAPIClient(
			t.Context(),
			datasource.MavenRegistry{URL: "https://example.com", ReleasesEnabled: true},
			localRegistry,
			false,
			&http.Client{Transport: transport},
			nil,
		)
		if err != nil {
			t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
		}

		if _, err := client.GetVersions(t.Context(), "g", "a"); err != nil {
			t.Fatalf("GetVersions failed: %v", err)
		}
		if !transport.wasCalled() {
			t.Fatal("registry was not queried")
		}

		outsidePath := filepath.Join(outsideDir, "a", "maven-metadata.xml")
		if _, err := os.Stat(outsidePath); !os.IsNotExist(err) {
			t.Errorf("outside file was created, os.Stat() returned %v", err)
		}
	})
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

func TestParseMavenRegistryURL(t *testing.T) {
	tests := []struct {
		input       string
		wantMirror  string
		wantOrigins []string
	}{
		{
			input:       "",
			wantMirror:  "",
			wantOrigins: nil,
		},
		{
			input:       "https://mirror.example.com/maven2",
			wantMirror:  "https://mirror.example.com/maven2",
			wantOrigins: nil,
		},
		{
			input:       "https://mirror.example.com/maven2[https://repo1.maven.org/maven2]",
			wantMirror:  "https://mirror.example.com/maven2",
			wantOrigins: []string{"https://repo1.maven.org/maven2"},
		},
		{
			input:       "https://mirror.example.com/maven2[https://repo.maven.apache.org/maven2,https://repo1.maven.org/maven2]",
			wantMirror:  "https://mirror.example.com/maven2",
			wantOrigins: []string{"https://repo.maven.apache.org/maven2", "https://repo1.maven.org/maven2"},
		},
		{
			input:       " https://mirror.example.com/maven2 [ https://repo.maven.apache.org/maven2 , https://repo1.maven.org/maven2 ] ",
			wantMirror:  "https://mirror.example.com/maven2",
			wantOrigins: []string{"https://repo.maven.apache.org/maven2", "https://repo1.maven.org/maven2"},
		},
	}

	for _, tc := range tests {
		gotMirror, gotOrigins := datasource.ParseMavenRegistryURL(tc.input)
		if gotMirror != tc.wantMirror {
			t.Errorf("ParseMavenRegistryURL(%q) mirror: got %q, want %q", tc.input, gotMirror, tc.wantMirror)
		}
		if !reflect.DeepEqual(gotOrigins, tc.wantOrigins) {
			t.Errorf("ParseMavenRegistryURL(%q) origins: got %v, want %v", tc.input, gotOrigins, tc.wantOrigins)
		}
	}
}

func TestMavenRegistryURLReplacementWithExplicitOrigins(t *testing.T) {
	mirrorSrv := clienttest.NewMockHTTPServer(t)
	flagVal := mirrorSrv.URL + "[https://repo.maven.apache.org/maven2,https://repo1.maven.org/maven2,https://rootonly.example.com]"

	client, err := datasource.NewMavenRegistryAPIClient(
		t.Context(),
		datasource.MavenRegistry{URL: flagVal, ReleasesEnabled: true},
		"",
		false,
		&http.Client{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
	}

	mirrorSrv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	// Adding explicit Maven Central URL should be rewritten to mirror and added to registries in order.
	if err := client.AddRegistry(t.Context(), datasource.MavenRegistry{
		URL:             "https://repo1.maven.org/maven2/",
		ID:              "central",
		ReleasesEnabled: true,
	}); err != nil {
		t.Fatalf("AddRegistry failed: %v", err)
	}

	if len(client.GetRegistries()) != 1 || client.GetRegistries()[0].URL != mirrorSrv.URL {
		t.Errorf("Expected 1 registry with replaced URL %s, got: %v", mirrorSrv.URL, client.GetRegistries())
	}

	// Project should be fetched from mirror.
	gotProj, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("GetProject failed: %v", err)
	}
	if gotProj.GroupID != "org.example" || gotProj.ArtifactID != "x.y.z" {
		t.Errorf("Unexpected project fetched: %v", gotProj)
	}

	// Adding a non-replaced repository should still be added to registries.
	thirdPartySrv := clienttest.NewMockHTTPServer(t)
	if err := client.AddRegistry(t.Context(), datasource.MavenRegistry{
		URL:             thirdPartySrv.URL,
		ID:              "spring-plugins",
		ReleasesEnabled: true,
	}); err != nil {
		t.Fatalf("AddRegistry failed: %v", err)
	}
	if len(client.GetRegistries()) != 2 {
		t.Errorf("Expected 2 registries in total, got %d", len(client.GetRegistries()))
	}
}
