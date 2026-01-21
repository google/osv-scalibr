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

package circleci_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/circleci"
)

func TestPersonalAccessTokenValidator_Valid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Circle-Token") == testPAT {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"name":"Test User","login":"testuser","id":"test-id"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`Invalid token provided.`))
		}
	}))
	defer server.Close()

	validator := circleci.NewPersonalAccessTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.PersonalAccessToken{Token: testPAT}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationValid)
	}
}

func TestPersonalAccessTokenValidator_Invalid(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Invalid token provided.`))
	}))
	defer server.Close()

	validator := circleci.NewPersonalAccessTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.PersonalAccessToken{Token: "CCIPAT_invalid_token"}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationInvalid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationInvalid)
	}
}

func TestProjectTokenValidator_Valid_200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && username == testProject && password == "" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vcs_url":"https://github.com/test/repo"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`Invalid token provided.`))
		}
	}))
	defer server.Close()

	validator := circleci.NewProjectTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.ProjectToken{Token: testProject}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationValid)
	}
}

func TestProjectTokenValidator_Valid_404WithNotFound(t *testing.T) {
	// This test validates that a 404 with the message "Not Found"
	// is treated as VALID (the token authenticated but the project doesn't exist)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if ok && username == testProject && password == "" {
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"message":"Not Found"}`))
		} else {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`Invalid token provided.`))
		}
	}))
	defer server.Close()

	validator := circleci.NewProjectTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.ProjectToken{Token: testProject}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationValid {
		t.Errorf("Validate() status = %v, want %v (404 with 'Not Found' should be valid)", status, veles.ValidationValid)
	}
}

func TestProjectTokenValidator_Invalid_401(t *testing.T) {
	// This test validates that a 401 with "Invalid token provided." is treated as INVALID
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Invalid token provided.`))
	}))
	defer server.Close()

	validator := circleci.NewProjectTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.ProjectToken{Token: "CCIPRJ_invalid_token"}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationInvalid {
		t.Errorf("Validate() status = %v, want %v (401 should be invalid)", status, veles.ValidationInvalid)
	}
}

func TestProjectTokenValidator_Invalid_NoBasicAuth(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`Invalid token provided.`))
	}))
	defer server.Close()

	validator := circleci.NewProjectTokenValidator()
	validator.Endpoint = server.URL

	secret := circleci.ProjectToken{Token: ""}
	status, err := validator.Validate(context.Background(), secret)
	if err != nil {
		t.Fatalf("Validate() error = %v, want nil", err)
	}
	if status != veles.ValidationInvalid {
		t.Errorf("Validate() status = %v, want %v", status, veles.ValidationInvalid)
	}
}
