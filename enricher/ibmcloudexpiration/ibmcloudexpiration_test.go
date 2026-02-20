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

package ibmcloudexpiration

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/ibmclouduserkey"
)

const validFirstResponse = `{"access_token":"eyJr_vvuqS-22jyUwNSsCqQ","refresh_token":"not_supported","ims_user_id":1234,"token_type":"Bearer","expires_in":3600,"expiration":1771544571,"scope":"ibm openid"}`
const validSecondResponseExpiring = `{"id":"ApiKey-e","entity_tag":"1-03de16","crn":"crn:v1:bluemix:public:iam-identity::a/a57a730F::apikey:ApiKey-ebaf10","locked":false,"disabled":false,"created_at":"2026-02-19T18:59+0000","created_by":"IBMid-667000UDPI","modified_at":"2026-02-19T18:59+0000","expires_at":"2026-03-21T18:59+0000","support_sessions":false,"action_when_leaked":"disable","name":"test2","description":"test2","iam_id":"IBMid-DPI","account_id":"a5e20","leaked":false}`
const validSecondResponseNonExpiring = `{"id":"ApiKey-5","entity_tag":"2-9a7","crn":"crn:v1:bluemix:public:iam-identity::a/a57a730F::apikey:ApiKey-526c5","locked":false,"disabled":false,"created_at":"2026-02-19T18:44+0000","created_by":"IBMid-667000UDPI","modified_at":"2026-02-19T18:48+0000","support_sessions":false,"action_when_leaked":"delete","name":"Test","description":"","iam_id":"IBMid-66I","account_id":"a57a","leaked":false}`

func TestEnrich_DefiniteExpireTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/identity/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validFirstResponse))
		} else if r.Method == http.MethodGet && r.URL.Path == "/v1/apikeys/details" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validSecondResponseExpiring))
		} else {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: ibmclouduserkey.IBMCloudUserSecret{Key: "1234"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok, ok := inv.Secrets[0].Secret.(ibmclouduserkey.IBMCloudUserSecret)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}
	if *tok.Metadata.ExpireTime != "2026-03-21T18:59+0000" || tok.Metadata.NeverExpires != false {
		t.Errorf("unexpected lifetime: %s", *tok.Metadata.ExpireTime)
	}
}

func TestEnrich_IndefiniteExpireTime(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/identity/token" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validFirstResponse))
		} else if r.Method == http.MethodGet && r.URL.Path == "/v1/apikeys/details" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(validSecondResponseNonExpiring))
		} else {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: ibmclouduserkey.IBMCloudUserSecret{Key: "1234"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok, ok := inv.Secrets[0].Secret.(ibmclouduserkey.IBMCloudUserSecret)
	if !ok {
		t.Fatalf("unexpected type: %T", inv.Secrets[0].Secret)
	}
	if tok.Metadata.ExpireTime != nil || tok.Metadata.NeverExpires != true {
		t.Errorf("unexpected lifetime: %s", *tok.Metadata.ExpireTime)
	}
}

func TestEnrich_SkipsOnNon200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	e := NewWithBaseURL(srv.URL)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: ibmclouduserkey.IBMCloudUserSecret{Key: "1234"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(ibmclouduserkey.IBMCloudUserSecret)
	if tok.Metadata != nil {
		t.Errorf("should not enrich on non-200: %+v", tok)
	}
}

func TestEnrich_ConnectionError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	base := srv.URL
	srv.Close()

	e := NewWithBaseURL(base)
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: ibmclouduserkey.IBMCloudUserSecret{Key: "1234"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
	tok := inv.Secrets[0].Secret.(ibmclouduserkey.IBMCloudUserSecret)
	if tok.Metadata != nil {
		t.Errorf("unexpected enrichment on connection error: %+v", tok)
	}
}

func TestEnrich_SkipsNonIBMCloudSecret(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: struct{ X string }{X: "noop"}}}}
	if err := e.Enrich(context.Background(), &enricher.ScanInput{}, inv); err != nil {
		t.Fatalf("Enrich error: %v", err)
	}
}

func TestEnrich_ContextCanceled(t *testing.T) {
	e := New()
	inv := &inventory.Inventory{Secrets: []*inventory.Secret{{Secret: ibmclouduserkey.IBMCloudUserSecret{Key: "1234"}}}}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := e.Enrich(ctx, &enricher.ScanInput{}, inv); err == nil {
		t.Fatalf("expected context error, got nil")
	}
}
