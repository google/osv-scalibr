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

package gitlabjobtoken

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/gitlab"
)

const (
	validJobResponse = `{
  "id": 1234567890,
  "status": "running",
  "user": {
    "id": 9876543,
    "username": "example-user"
  },
  "pipeline": {
    "id": 9876543210,
    "project_id": 12345678
  }
}`
)

func TestEnrich_Success(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// The path should match /api/v4/job
		if r.URL.Path != "/api/v4/job" {
			t.Logf("Unexpected path: %s", r.URL.Path)
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		if r.Method != http.MethodGet {
			t.Logf("Unexpected method: %s", r.Method)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Job-Token") != "test-token" {
			t.Logf("Unexpected token: %s", r.Header.Get("Job-Token"))
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validJobResponse))
	}))
	defer srv.Close()

	// Use the full test server URL (includes http://)
	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token:    "test-token",
				Hostname: srv.URL, // Full URL with protocol
			},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok, ok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}

	if tok.JobID != 1234567890 {
		t.Errorf("unexpected JobID: got %d, want 1234567890", tok.JobID)
	}
	if tok.Status != "running" {
		t.Errorf("unexpected Status: got %s, want running", tok.Status)
	}
	if tok.Username != "example-user" {
		t.Errorf("unexpected Username: got %s, want example-user", tok.Username)
	}
	if tok.ProjectID != 12345678 {
		t.Errorf("unexpected ProjectID: got %d, want 12345678", tok.ProjectID)
	}
}

func TestEnrich_DefaultHostname(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validJobResponse))
	}))
	defer srv.Close()

	e := New()
	// Token without hostname should default to gitlab.com
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token: "test-token",
				// Hostname is empty, should default to gitlab.com
			},
		}},
	}

	// This will fail to connect to gitlab.com, but that's expected
	// We're just testing that it doesn't crash
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	// Should not be enriched due to connection failure
	if tok.JobID != 0 {
		t.Errorf("should not enrich on connection error: %+v", tok)
	}
}

func TestEnrich_SkipsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token:    "test-token",
				Hostname: srv.URL,
			},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if tok.JobID != 0 {
		t.Errorf("should not enrich on non-200: %+v", tok)
	}
}

func TestEnrich_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	baseURL := srv.URL
	srv.Close()

	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token:    "test-token",
				Hostname: baseURL,
			},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if tok.JobID != 0 {
		t.Errorf("unexpected enrichment on connection error: %+v", tok)
	}
}

func TestEnrich_InvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"invalid json`))
	}))
	defer srv.Close()

	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token:    "test-token",
				Hostname: srv.URL,
			},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if tok.JobID != 0 {
		t.Errorf("should not enrich on invalid JSON: %+v", tok)
	}
}

func TestEnrich_SkipsNonGitLabToken(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: struct{ X string }{X: "noop"},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
}

func TestEnrich_SkipsEmptyToken(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token: "",
			},
		}},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	tok := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if tok.JobID != 0 {
		t.Errorf("should not enrich empty token: %+v", tok)
	}
}

func TestEnrich_ContextCanceled(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{{
			Secret: gitlab.CIJobToken{
				Token: "test-token",
			},
		}},
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if err := e.Enrich(ctx, &enricher.ScanInput{}, inv); err == nil {
		t.Fatalf("expected context error, got nil")
	}
}

func TestEnrich_MultipleSecrets(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validJobResponse))
	}))
	defer srv.Close()

	e := New()
	inv := &inventory.Inventory{
		Secrets: []*inventory.Secret{
			{Secret: gitlab.CIJobToken{Token: "token1", Hostname: srv.URL}},
			{Secret: gitlab.CIJobToken{Token: "token2", Hostname: srv.URL}},
			{Secret: struct{ X string }{X: "other"}}, // Non-GitLab secret
		},
	}

	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}

	// Check first token was enriched
	tok1 := inv.Secrets[0].Secret.(gitlab.CIJobToken)
	if tok1.JobID != 1234567890 {
		t.Errorf("first token not enriched: %+v", tok1)
	}

	// Check second token was enriched
	tok2 := inv.Secrets[1].Secret.(gitlab.CIJobToken)
	if tok2.JobID != 1234567890 {
		t.Errorf("second token not enriched: %+v", tok2)
	}

	// Check third secret was not modified
	if _, ok := inv.Secrets[2].Secret.(struct{ X string }); !ok {
		t.Errorf("third secret type changed: %T", inv.Secrets[2].Secret)
	}
}
