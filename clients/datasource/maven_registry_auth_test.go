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
	"reflect"
	"testing"

	"github.com/google/osv-scalibr/clients/clienttest"
)

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

func TestDefaultRegistryUsesSettingsAuth(t *testing.T) {
	var authHeaders []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeaders = append(authHeaders, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Registry\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, _ = w.Write([]byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))
	}))
	defer srv.Close()

	client, err := NewMavenRegistryAPIClient(t.Context(), MavenRegistry{
		URL:             srv.URL,
		ID:              "trusted",
		ReleasesEnabled: true,
	}, "", true)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient() error = %v", err)
	}
	client.registryAuths = map[string]*HTTPAuthentication{
		"trusted": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			Username:         "demo-user",
			Password:         "demo-pass",
		},
	}

	if _, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0"); err != nil {
		t.Fatalf("GetProject() error = %v", err)
	}

	want := []string{"", "Basic ZGVtby11c2VyOmRlbW8tcGFzcw=="}
	if !reflect.DeepEqual(authHeaders, want) {
		t.Fatalf("authorization headers got = %v, want %v", authHeaders, want)
	}
}

func TestAddedRegistryDoesNotUseSettingsAuth(t *testing.T) {
	var attackerAuthHeaders []string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attackerAuthHeaders = append(attackerAuthHeaders, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate", "Basic realm=\"Attacker\"")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		_, _ = w.Write([]byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))
	}))
	defer attacker.Close()

	trusted := clienttest.NewMockHTTPServer(t)
	trusted.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`
	<project>
	  <groupId>org.example</groupId>
	  <artifactId>x.y.z</artifactId>
	  <version>1.0.0</version>
	</project>
	`))

	client, err := NewMavenRegistryAPIClient(t.Context(), MavenRegistry{
		URL:             trusted.URL,
		ID:              "trusted",
		ReleasesEnabled: true,
	}, "", true)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient() error = %v", err)
	}
	client.registryAuths = map[string]*HTTPAuthentication{
		"attacker": {
			SupportedMethods: []HTTPAuthMethod{AuthBasic},
			Username:         "demo-user",
			Password:         "demo-pass",
		},
	}

	if err := client.AddRegistry(t.Context(), MavenRegistry{
		URL:             attacker.URL,
		ID:              "attacker",
		ReleasesEnabled: true,
	}); err != nil {
		t.Fatalf("AddRegistry() error = %v", err)
	}

	if _, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0"); err != nil {
		t.Fatalf("GetProject() error = %v", err)
	}

	want := []string{""}
	if !reflect.DeepEqual(attackerAuthHeaders, want) {
		t.Fatalf("attacker authorization headers got = %v, want %v", attackerAuthHeaders, want)
	}
}
