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
	"context"
	"testing"
)

func TestAddRegistry_RejectsUntrustedURL(t *testing.T) {
	origLookup := lookupHost
	t.Cleanup(func() { lookupHost = origLookup })

	cases := []struct {
		name      string
		url       string
		resolveTo []string
	}{
		{name: "non-http scheme", url: "file:///etc/passwd", resolveTo: nil},
		{name: "ftp scheme", url: "ftp://example.com/repo", resolveTo: []string{"203.0.113.10"}},
		{name: "artifactregistry scheme from pom.xml", url: "artifactregistry://evil.example/repo", resolveTo: []string{"203.0.113.11"}},
		{name: "loopback literal", url: "http://127.0.0.1/repo", resolveTo: []string{"127.0.0.1"}},
		{name: "rfc1918 literal", url: "http://10.0.0.1/repo", resolveTo: []string{"10.0.0.1"}},
		{name: "link-local literal", url: "http://169.254.169.254/repo", resolveTo: []string{"169.254.169.254"}},
		{name: "dns-rebind to private", url: "http://evil.example.com/repo", resolveTo: []string{"192.168.1.1"}},
		{name: "empty host", url: "http:///repo", resolveTo: nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupHost = func(string) ([]string, error) { return tc.resolveTo, nil }
			client, err := NewMavenRegistryAPIClient(
				context.Background(),
				MavenRegistry{URL: "https://repo.maven.apache.org/maven2", ReleasesEnabled: true},
				"",
				true,
			)
			if err != nil {
				t.Fatalf("NewMavenRegistryAPIClient: %v", err)
			}
			err = client.AddRegistry(context.Background(), MavenRegistry{URL: tc.url, ID: "hostile"})
			if err == nil {
				t.Fatalf("AddRegistry(%q) = nil, want error", tc.url)
			}
			if got := client.GetRegistries(); len(got) != 0 {
				t.Errorf("registry was added despite validation failure: %+v", got)
			}
		})
	}
}

func TestAddRegistry_ClearsTrustedForAuth(t *testing.T) {
	origLookup := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.42"}, nil }
	t.Cleanup(func() { lookupHost = origLookup })

	client, err := NewMavenRegistryAPIClient(
		context.Background(),
		MavenRegistry{URL: "https://repo.maven.apache.org/maven2", ReleasesEnabled: true},
		"",
		true,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient: %v", err)
	}

	// The caller tries to smuggle in TrustedForAuth=true; AddRegistry must drop it.
	if err := client.AddRegistry(
		context.Background(),
		MavenRegistry{URL: "https://attacker.example/repo", ID: "hostile", TrustedForAuth: true},
	); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	regs := client.GetRegistries()
	if len(regs) != 1 {
		t.Fatalf("expected 1 added registry, got %d", len(regs))
	}
	if regs[0].TrustedForAuth {
		t.Errorf("AddRegistry left TrustedForAuth=true for an untrusted registry")
	}
}

func TestAddRegistry_UntrustedCannotOverwriteDefault(t *testing.T) {
	origLookup := lookupHost
	lookupHost = func(string) ([]string, error) { return []string{"203.0.113.55"}, nil }
	t.Cleanup(func() { lookupHost = origLookup })

	client, err := NewMavenRegistryAPIClient(
		context.Background(),
		MavenRegistry{URL: "https://repo.maven.apache.org/maven2", ID: "central", ReleasesEnabled: true},
		"",
		true,
	)
	if err != nil {
		t.Fatalf("NewMavenRegistryAPIClient: %v", err)
	}

	// A pom.xml-sourced registry whose ID collides with the default
	// must not inherit the default registry's trusted status.
	if err := client.AddRegistry(
		context.Background(),
		MavenRegistry{URL: "https://attacker.example/repo", ID: "central", TrustedForAuth: true},
	); err != nil {
		t.Fatalf("AddRegistry: %v", err)
	}
	if client.defaultRegistry.TrustedForAuth {
		t.Errorf("default registry was marked trusted after an untrusted overwrite")
	}
}

func TestAuthFor_OnlyTrustedRegistriesReceiveCredentials(t *testing.T) {
	m := &MavenRegistryAPIClient{
		registryAuths: map[string]*HTTPAuthentication{
			"central": {Username: "u", Password: "p"},
		},
	}
	trusted := MavenRegistry{ID: "central", TrustedForAuth: true}
	if got := m.authFor(trusted); got == nil {
		t.Errorf("authFor(trusted) = nil, want credentials")
	}
	untrusted := MavenRegistry{ID: "central", TrustedForAuth: false}
	if got := m.authFor(untrusted); got != nil {
		t.Errorf("authFor(untrusted) returned credentials, leak")
	}
}
