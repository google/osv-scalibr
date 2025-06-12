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

// This test uses datasource package in order to test auth data
package datasource

import (
	"context"
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/google/osv-scalibr/clients/clienttest"
)

func TestWithoutRegistriesMaintainsAuthData(t *testing.T) {
	// Create mock server to test auth is maintained
	srv := clienttest.NewMockHTTPServer(t)

	// Create original client with multiple registries
	client, _ := NewMavenRegistryAPIClient(MavenRegistry{URL: srv.URL, ReleasesEnabled: true}, "")
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
	if err := client.AddRegistry(testRegistry1); err != nil {
		t.Fatalf("failed to add registry %s: %v", testRegistry1.URL, err)
	}
	if err := client.AddRegistry(testRegistry2); err != nil {
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
	GetVersions, err := clientWithoutReg.GetVersions(context.Background(), "org.example", "x.y.z")
	if err != nil {
		t.Fatalf("failed to get versions for Maven package %s:%s: %v", "org.example", "x.y.z", err)
	}

	if len(GetVersions) != 1 {
		t.Errorf("WithoutRegistries() returned client with %d versions, want 1", len(GetVersions))
	}
}
