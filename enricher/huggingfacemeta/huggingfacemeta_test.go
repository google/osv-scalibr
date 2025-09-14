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

package huggingfacemeta_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/enricher/huggingfacemeta"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
)

type testEnricherSubCase struct {
	name             string
	input            inventory.Inventory
	Role             string
	FineGrainedScope []string
	want             inventory.Inventory
}

func TestEnricher(t *testing.T) {
	path := "/foo/bar/key.json"
	cases := []struct {
		name string
		subs []testEnricherSubCase
	}{
		{
			name: "Append Role and Fine Grained Scopes",
			subs: []testEnricherSubCase{
				{
					name: "supported",
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   huggingfaceapikey.HuggingfaceAPIKey{Key: "foo"},
								Location: path,
							},
						},
					},
					Role:             "read",
					FineGrainedScope: []string{"inference.endpoints.infer.write", "repo.content.read"},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret: huggingfaceapikey.HuggingfaceAPIKey{
									Key:              "foo",
									Role:             "read",
									FineGrainedScope: []string{"inference.endpoints.infer.write", "repo.content.read"},
								},
								Location: path,
							},
						},
					},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sc := range tc.subs {
				t.Run(sc.name, func(t *testing.T) {
					// Mock Hugging Face API server responding with the desired Role and FineGrainedScope
					ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/api/whoami-v2" {
							http.NotFound(w, r)
							return
						}
						w.Header().Set("Content-Type", "application/json")
						resp := map[string]any{
							"auth": map[string]any{
								"accessToken": map[string]any{
									"role": sc.Role,
									"fineGrained": map[string]any{
										"scoped": []map[string]any{
											{"permissions": sc.FineGrainedScope},
										},
									},
								},
							},
						}
						_ = json.NewEncoder(w).Encode(resp)
					}))
					defer ts.Close()

					// Use enricher configured against the mock server
					enricher := huggingfacemeta.NewWithBaseURL(ts.URL)

					if err := enricher.Enrich(t.Context(), nil, &sc.input); err != nil {
						t.Errorf("Enrich() error: %v, want nil", err)
					}
					got := &sc.input
					want := &sc.want
					// We can rely on the order of Secrets in the inventory here, since the enricher is not supposed to change it.
					if diff := cmp.Diff(want, got, cmpopts.EquateErrors(), cmpopts.IgnoreTypes(time.Time{})); diff != "" {
						t.Errorf("Enrich() got diff (-want +got):\n%s", diff)
					}
				})
			}
		})
	}
}
