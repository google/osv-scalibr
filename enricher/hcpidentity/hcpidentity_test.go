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

package hcpidentity

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/hcp"
)

func TestEnrich_PopulatesServicePrincipal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/iam/2019-12-10/caller-identity" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
  "principal": {
    "id": "svc-abc@proj-123",
    "type": "PRINCIPAL_TYPE_SERVICE",
    "service": {
      "id": "svc-abc@proj-123",
      "name": "svc-abc",
      "organization_id": "org-001",
      "project_id": "proj-123"
    },
    "group_ids": ["g1","g2"]
  }
}`))
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: hcp.AccessToken{Token: "t"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok, ok := inv.Secrets[0].Secret.(hcp.AccessToken)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}
	if tok.OrganizationID != "org-001" || tok.ProjectID != "proj-123" || tok.PrincipalID != "svc-abc@proj-123" || tok.ServiceName != "svc-abc" || tok.PrincipalType != "PRINCIPAL_TYPE_SERVICE" {
		t.Errorf("unexpected identity: %+v", tok)
	}
	if tok.UserEmail != "" || tok.UserID != "" {
		t.Errorf("unexpected user email or user id: %+v", tok)
	}
	if len(tok.GroupIDs) != 2 || tok.GroupIDs[0] != "g1" || tok.GroupIDs[1] != "g2" {
		t.Errorf("unexpected group ids: %+v", tok.GroupIDs)
	}
}

func TestEnrich_SkipsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: hcp.AccessToken{Token: "t"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(hcp.AccessToken)
	if tok.OrganizationID != "" || tok.ProjectID != "" || tok.PrincipalID != "" || tok.ServiceName != "" || tok.PrincipalType != "" || len(tok.GroupIDs) != 0 {
		t.Errorf("should not enrich on non-200: %+v", tok)
	}
}

func TestEnrich_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()

	e := NewWithBaseURL(base)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: hcp.AccessToken{Token: "t"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(hcp.AccessToken)
	if tok.OrganizationID != "" {
		t.Errorf("unexpected enrichment on connection error: %+v", tok)
	}
}

func TestEnrich_SkipsNonHCPSecret(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: struct{ X string }{X: "noop"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
}

func TestEnrich_ContextCanceled(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: hcp.AccessToken{Token: "t"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Enrich(ctx, &enricher.ScanInput{}, inv); err == nil {
		t.Fatalf("expected context error, got nil")
	}
}
