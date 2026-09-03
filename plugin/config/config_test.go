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

package config_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/osv-scalibr/plugin/config"
)

func TestDefaultClientFactories_HTTPClient_Caching(t *testing.T) {
	cf := config.NewDefaultClientFactories("")
	defer cf.Close()

	c1 := cf.HTTPClient()
	c2 := cf.HTTPClient()

	if c1 == nil {
		t.Fatal("HTTPClient() returned nil")
	}
	if c1 != c2 {
		t.Errorf("HTTPClient() did not return cached client: %p != %p", c1, c2)
	}
}

func TestDefaultClientFactories_Close_ClearsCache(t *testing.T) {
	cf := config.NewDefaultClientFactories("")

	c1 := cf.HTTPClient()
	if err := cf.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}

	c2 := cf.HTTPClient()
	if c1 == c2 {
		t.Errorf("HTTPClient() returned cached client after Close(): %p == %p", c1, c2)
	}
}

func TestDefaultClientFactories_Concurrency(t *testing.T) {
	cf := config.NewDefaultClientFactories("")
	defer cf.Close()

	var wg sync.WaitGroup
	const goroutines = 10
	clients := make([]*http.Client, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			clients[idx] = cf.HTTPClient()
		}(i)
	}
	wg.Wait()

	first := clients[0]
	if first == nil {
		t.Fatal("First client is nil")
	}
	for i := 1; i < goroutines; i++ {
		if clients[i] != first {
			t.Errorf("Client %d is different: %p != %p", i, clients[i], first)
		}
	}
}

func generateFakeCredentials(t *testing.T) string {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	keyBytes := x509.MarshalPKCS1PrivateKey(key)
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: keyBytes,
	})
	escapedKey := strings.ReplaceAll(string(keyPEM), "\n", "\\n")

	return fmt.Sprintf(`{
		"type": "service_account",
		"project_id": "fake-project",
		"private_key_id": "fake-key-id",
		"private_key": "%s",
		"client_email": "fake@fake-project.iam.gserviceaccount.com",
		"client_id": "fake-client-id",
		"auth_uri": "https://accounts.google.com/o/oauth2/auth",
		"token_uri": "https://oauth2.googleapis.com/token"
	}`, escapedKey)
}

func TestDefaultClientFactories_GoogleHTTPClient_Caching(t *testing.T) {
	fakeCredentials := generateFakeCredentials(t)
	tmpFile, err := os.CreateTemp(t.TempDir(), "fake-creds-*.json")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	if _, err := tmpFile.WriteString(fakeCredentials); err != nil {
		t.Fatalf("failed to write fake creds: %v", err)
	}
	if err := tmpFile.Close(); err != nil {
		t.Fatalf("failed to close temp file: %v", err)
	}

	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", tmpFile.Name())

	cf := config.NewDefaultClientFactories("")
	defer cf.Close()

	ctx := context.Background()
	scope := "https://www.googleapis.com/auth/cloud-platform"

	c1, err := cf.GoogleHTTPClient(ctx, scope)
	if err != nil {
		t.Fatalf("GoogleHTTPClient() failed: %v", err)
	}
	c2, err := cf.GoogleHTTPClient(ctx, scope)
	if err != nil {
		t.Fatalf("GoogleHTTPClient() failed: %v", err)
	}

	if c1 == nil {
		t.Fatal("GoogleHTTPClient() returned nil")
	}
	if c1 != c2 {
		t.Errorf("GoogleHTTPClient() did not return cached client: %p != %p", c1, c2)
	}

	c3, err := cf.GoogleHTTPClient(ctx, "different-scope")
	if err != nil {
		t.Fatalf("GoogleHTTPClient() failed: %v", err)
	}
	if c1 == c3 {
		t.Errorf("GoogleHTTPClient() returned same client for different scope")
	}
}

func TestDefaultClientFactories_UserAgent(t *testing.T) {
	const ua = "test-user-agent"
	cf := config.NewDefaultClientFactories(ua)
	defer cf.Close()

	var capturedUA string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedUA = r.Header.Get("User-Agent")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	httpClient := cf.HTTPClient()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		t.Fatalf("failed to make request: %v", err)
	}
	resp.Body.Close()

	if capturedUA != ua {
		t.Errorf("expected User-Agent %q, got %q", ua, capturedUA)
	}
}
