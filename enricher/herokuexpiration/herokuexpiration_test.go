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

package herokuexpiration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/herokuplatformkey"
)

const (
	validResponse = `[
  {
    "access_token": {
      "expires_in": 123456,
      "id": "7",
      "token": "HRKU"
    },
    "client": null,
    "created_at": "2026-01-16T15:57:25Z",
    "description": "Long-lived user authorization",
    "grant": null,
    "id": "7",
    "refresh_token": null,
    "session": null,
    "scope": [
      "global"
    ],
    "updated_at": "2026-01-16T15:57:25Z",
    "user": {
      "id": "cb",
      "email": "google",
      "full_name": "google"
    }
  },
  {
    "access_token": {
      "expires_in": null,
      "id": "bf",
      "token": "TRKU"
    },
    "client": null,
    "created_at": "2026-01-16T14:21:36Z",
    "description": "Long-lived user authorization",
    "grant": null,
    "id": "bf",
    "refresh_token": null,
    "session": null,
    "scope": [
      "global"
    ],
    "updated_at": "2026-01-16T15:32:59Z",
    "user": {
      "id": "cb",
      "email": "google",
      "full_name": "google"
    }
  }
]`
)

func TestEnrich_DefiniteExpireTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/oauth/authorizations" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validResponse))
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: herokuplatformkey.HerokuSecret{Key: "HRKU"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok, ok := inv.Secrets[0].Secret.(herokuplatformkey.HerokuSecret)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}
	if *tok.Metadata.ExpireTime != 123456*time.Second || tok.Metadata.NeverExpires != false {
		t.Errorf("unexpected lifetime: %s", *tok.Metadata.ExpireTime)
	}
}

func TestEnrich_IndefiniteExpireTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/oauth/authorizations" {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(validResponse))
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: herokuplatformkey.HerokuSecret{Key: "TRKU"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok, ok := inv.Secrets[0].Secret.(herokuplatformkey.HerokuSecret)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}
	if tok.Metadata.ExpireTime != nil || tok.Metadata.NeverExpires != true {
		t.Errorf("unexpected lifetime: %s", *tok.Metadata.ExpireTime)
	}
}

func TestEnrich_SkipsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: herokuplatformkey.HerokuSecret{Key: "HRKU"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(herokuplatformkey.HerokuSecret)
	if tok.Metadata != nil {
		t.Errorf("should not enrich on non-200: %+v", tok)
	}
}

func TestEnrich_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()

	e := NewWithBaseURL(base)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: herokuplatformkey.HerokuSecret{Key: "HRKU"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(herokuplatformkey.HerokuSecret)
	if tok.Metadata != nil {
		t.Errorf("unexpected enrichment on connection error: %+v", tok)
	}
}

func TestEnrich_SkipsNonHerokuSecret(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: struct{ X string }{X: "noop"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
}

func TestEnrich_ContextCanceled(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: herokuplatformkey.HerokuSecret{Key: "HRKU"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Enrich(ctx, &enricher.ScanInput{}, inv); err == nil {
		t.Fatalf("expected context error, got nil")
	}
}
