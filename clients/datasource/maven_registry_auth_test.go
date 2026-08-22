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

package datasource

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/clients/clienttest"
)

func TestAddRegistryRejectsHTTPWhenCredentialsConfigured(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	client.registryAuths = map[string]*HTTPAuthentication{
		"private-repo": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			Username:         "user",
			Password:         "pass",
		},
	}

	err := client.AddRegistry(t.Context(), MavenRegistry{
		URL:             "http://attacker.com/maven2/",
		ID:              "private-repo",
		ReleasesEnabled: true,
	})
	if err == nil {
		t.Error("AddRegistry() should reject http:// URL when credentials are configured, got nil error")
	}
}

func TestUpdateDefaultRegistryRejectsHTTPWhenCredentialsConfigured(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	// Default registry gets ID "default" when none is specified.
	client, _ := NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	client.registryAuths = map[string]*HTTPAuthentication{
		"default": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			Username:         "user",
			Password:         "pass",
		},
	}

	err := client.AddRegistry(t.Context(), MavenRegistry{
		URL:             "http://attacker.com/maven2/",
		ID:              "default",
		ReleasesEnabled: true,
	})
	if err == nil {
		t.Error("AddRegistry() should reject http:// URL when updating default registry with credentials, got nil error")
	}
}

func TestAddRegistryAllowsHTTPSWhenCredentialsConfigured(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, _ := NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	client.registryAuths = map[string]*HTTPAuthentication{
		"private-repo": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			Username:         "user",
			Password:         "pass",
		},
	}

	err := client.AddRegistry(t.Context(), MavenRegistry{
		URL:             "https://private.maven.org/maven2/",
		ID:              "private-repo",
		ReleasesEnabled: true,
	})
	if err != nil {
		t.Errorf("AddRegistry() should allow https:// URL when credentials are configured, got error: %v", err)
	}
}

func TestWithoutRegistriesMaintainsAuthData(t *testing.T) {
	// Create mock server to test auth is maintained
	srv := clienttest.NewMockHTTPServer(t)

	// Create original client with multiple registries
	client, _ := NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	testRegistry1 := MavenRegistry{
		URL:             "https://test1.maven.org/maven2/",
		ID:              "test1",
		ReleasesEnabled: true,
	}
	testRegistry2 := MavenRegistry{
		URL:              "https://test2.maven.org/maven2/",
		ID:               "test2",
		SnapshotsEnabled: true,
	}
	if err := client.AddRegistry(t.Context(), testRegistry1); err != nil {
		t.Fatalf("failed to add registry %s: %v", testRegistry1.URL, err)
	}
	if err := client.AddRegistry(t.Context(), testRegistry2); err != nil {
		t.Fatalf("failed to add registry %s: %v", testRegistry2.URL, err)
	}

	// Directly modify registryAuths field in client
	testUsername := "testuser"
	testPassword := "testpass"
	auth := map[string]*HTTPAuthentication{
		"default": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			AlwaysAuth:       true,
			Username:         testUsername,
			Password:         testPassword,
		},
	}
	client.registryAuths = auth

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
	GetVersions, err := clientWithoutReg.GetVersions(t.Context(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}

	if len(GetVersions) != 1 {
		t.Errorf("WithoutRegistries() returned client with %d versions, want 1", len(GetVersions))
	}
}

// TestReplacedOriginDoesNotSendAuthToUnauthenticatedMirror tests security hardening to ensure
// that when a repository with private credentials is replaced by an unauthenticated mirror URL,
// no authentication is sent to the mirror.
func TestReplacedOriginDoesNotSendAuthToUnauthenticatedMirror(t *testing.T) {
	var authHeaderSent string
	mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaderSent = r.Header.Get("Authorization")
		if r.URL.Path == "/org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom" {
			w.WriteHeader(http.StatusOK)
			if _, err := w.Write([]byte(`
			<project>
			  <groupId>org.example</groupId>
			  <artifactId>x.y.z</artifactId>
			  <version>1.0.0</version>
			</project>
			`)); err != nil {
				t.Errorf("w.Write failed: %v", err)
			}
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer mirrorSrv.Close()

	flagVal := mirrorSrv.URL + "[https://private.corp.internal/maven2]"
	client, err := NewMavenRegistryAPIClient(
		t.Context(),
		MavenRegistry{URL: flagVal, ReleasesEnabled: true},
		"",
		false,
		&http.Client{},
		nil,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient failed: %v", err)
	}

	// Configure sensitive credentials for origin repo ID "private-repo" in settings.xml.
	client.registryAuths = map[string]*HTTPAuthentication{
		"private-repo": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			AlwaysAuth:       true,
			Username:         "secret_user",
			Password:         "secret_password",
		},
	}

	// Adding "private-repo" from POM is rewritten to the unauthenticated mirror.
	if err := client.AddRegistry(t.Context(), MavenRegistry{
		URL:             "https://private.corp.internal/maven2",
		ID:              "private-repo",
		ReleasesEnabled: true,
	}); err != nil {
		t.Fatalf("AddRegistry failed: %v", err)
	}

	gotProj, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
	if err != nil {
		t.Fatalf("GetProject failed: %v", err)
	}
	if gotProj.GroupID != "org.example" || gotProj.ArtifactID != "x.y.z" {
		t.Errorf("Unexpected project: %v", gotProj)
	}

	// Assert NO authentication header was sent to the mirror.
	if authHeaderSent != "" {
		t.Errorf("Expected no Authorization header sent to mirror, got %q", authHeaderSent)
	}
}
