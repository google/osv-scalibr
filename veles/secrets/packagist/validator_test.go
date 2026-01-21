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

package packagist_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/packagist"
)

func TestAPIKeyValidator_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth == "PACKAGIST-TOKEN packagist_ack_validkey1234567890abcdef1234567890abcdef1234567890abcdef" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`[]`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":"error","message":"An authentication exception occurred."}`))
	}))
	defer server.Close()

	validator := packagist.NewAPIKeyValidator()
	validator.Endpoint = server.URL

	key := packagist.APIKey{
		Key: "packagist_ack_validkey1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	status, err := validator.Validate(context.Background(), key)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationValid)
	}
}

func TestAPIKeyValidator_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":"error","message":"An authentication exception occurred."}`))
	}))
	defer server.Close()

	validator := packagist.NewAPIKeyValidator()
	validator.Endpoint = server.URL

	key := packagist.APIKey{
		Key: "packagist_ack_invalidkey1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	status, err := validator.Validate(context.Background(), key)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationInvalid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationInvalid)
	}
}

func TestAPISecretValidator_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		// Check that it's using HMAC-SHA256 authentication
		if !strings.HasPrefix(auth, "PACKAGIST-HMAC-SHA256") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// Check that required parameters are present
		if !strings.Contains(auth, "Key=") || !strings.Contains(auth, "Timestamp=") ||
			!strings.Contains(auth, "Cnonce=") || !strings.Contains(auth, "Signature=") {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		// For testing, accept any properly formatted HMAC request
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	validator := packagist.NewAPISecretValidator()
	// Override EndpointFunc to use test server
	validator.EndpointFunc = func(secret packagist.APISecret) (string, error) {
		if secret.Key == "" {
			return "", errors.New("API key not present")
		}
		return server.URL, nil
	}

	secret := packagist.APISecret{
		Secret: "packagist_acs_testsecret1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Key:    "packagist_ack_testkey1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationValid)
	}
}

func TestAPISecretValidator_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"status":"error","message":"An authentication exception occurred."}`))
	}))
	defer server.Close()

	validator := packagist.NewAPISecretValidator()
	// Override EndpointFunc to use test server
	validator.EndpointFunc = func(secret packagist.APISecret) (string, error) {
		if secret.Key == "" {
			return "", errors.New("API key not present")
		}
		return server.URL, nil
	}

	secret := packagist.APISecret{
		Secret: "packagist_acs_invalidsecret1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Key:    "packagist_ack_testkey1234567890abcdef1234567890abcdef1234567890abcdef",
	}

	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationInvalid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationInvalid)
	}
}

func TestAPISecretValidator_NoAPIKey(t *testing.T) {
	validator := packagist.NewAPISecretValidator()

	secret := packagist.APISecret{
		Secret: "packagist_acs_testsecret1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		Key:    "", // No key provided
	}

	status, err := validator.Validate(context.Background(), secret)
	// When Key is empty, HTTPHeaders returns nil, which should cause validation to fail
	if err == nil {
		t.Fatal("Validate() error = nil, want error when Key is empty")
	}
	if status != veles.ValidationFailed {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationFailed)
	}
}
