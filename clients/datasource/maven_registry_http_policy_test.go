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
	"strings"
	"testing"

	"github.com/google/osv-scalibr/clients/clienttest"
	"github.com/google/osv-scalibr/clients/datasource"
)

// External HTTP registry should be blocked before any network call.
func TestExternalHTTPRegistry_BlockedByDefault(t *testing.T) {
	client, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "http://example.invalid/maven2")
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	_, err = client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
	if err == nil {
		t.Fatal("expected block error, got nil")
	}
	if !strings.Contains(err.Error(), "blocked") {
		t.Errorf("expected block error, got: %v", err)
	}
}

// Explicit allowlist entry lets the request through.
func TestExternalHTTPRegistry_AllowOptIn(t *testing.T) {
	srv := clienttest.NewMockHTTPServer(t)
	client, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), srv.URL)
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}
	// httptest binds 127.0.0.1 which is always allowed, but call this anyway
	// so the allowlist code path is exercised on a real fetch.
	client.AllowInsecureHTTPHost("example.invalid")

	srv.SetResponse(t, "org/example/x.y.z/1.0.0/x.y.z-1.0.0.pom", []byte(`<project/>`))
	if _, err := client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0"); err != nil {
		t.Fatalf("expected fetch to succeed, got: %v", err)
	}
}

// Loopback http should never be blocked. Connection-refused is fine since the
// port is bogus; we just need to confirm the block error doesn't fire.
func TestLoopbackHTTPRegistry_AlwaysAllowed(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1"} {
		t.Run(host, func(t *testing.T) {
			client, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "http://"+host+":1/maven2")
			if err != nil {
				t.Fatalf("constructor: %v", err)
			}
			_, err = client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
			if err != nil && strings.Contains(err.Error(), "blocked") {
				t.Errorf("loopback host %q should not be blocked: %v", host, err)
			}
		})
	}
}

// pom.xml-discovered registry should be subject to the same block. This is
// the actual attack path called out in osv-scanner#2672.
func TestExternalHTTPRegistry_AddRegistryAlsoBlocked(t *testing.T) {
	client, err := datasource.NewDefaultMavenRegistryAPIClient(t.Context(), "http://default.invalid/maven2")
	if err != nil {
		t.Fatalf("constructor: %v", err)
	}

	if err := client.AddRegistry(t.Context(), datasource.MavenRegistry{
		ID:              "attacker",
		URL:             "http://malicious.invalid/maven2",
		ReleasesEnabled: true,
	}); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}

	_, err = client.GetProject(t.Context(), "org.example", "x.y.z", "1.0.0")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	// Both registries are blocked, and GetProject joins their errors. Verify
	// the joined message names both so we know neither one snuck through.
	for _, want := range []string{"blocked", "default.invalid", "malicious.invalid"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("expected %q in joined error, got: %v", want, err)
		}
	}
}
