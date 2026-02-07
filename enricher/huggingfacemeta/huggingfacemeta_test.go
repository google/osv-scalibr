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

func TestEnricher(t *testing.T) {
	type testEnricherSubCase struct {
		name       string
		respBody   any
		statusCode int
		input      inventory.Inventory
		want       inventory.Inventory
		wantErr    error
	}
	validRespBody := func(role string, fineGrainedScope []string) map[string]any {
		return map[string]any{
			"auth": map[string]any{
				"accessToken": map[string]any{
					"role": role,
					"fineGrained": map[string]any{
						"scoped": []map[string]any{
							{"permissions": fineGrainedScope},
						},
					},
				},
			},
		}
	}
	path := "/foo/bar/key.json"
	cases := []struct {
		name string
		subs []testEnricherSubCase
	}{
		{
			name: "Append_role_and_Fine_Grained_Scopes",
			subs: []testEnricherSubCase{
				{
					name:       "supported",
					statusCode: http.StatusOK,
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   huggingfaceapikey.HuggingfaceAPIKey{Key: "foo"},
								Location: path,
							},
						},
					},
					respBody: validRespBody("read",
						[]string{"inference.endpoints.infer.write", "repo.content.read"}),
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
				{
					name:       "no json response",
					statusCode: http.StatusOK,
					wantErr:    cmpopts.AnyError,
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   huggingfaceapikey.HuggingfaceAPIKey{Key: "foo2"},
								Location: path,
							},
						},
					},
					respBody: "response body is not json",
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret: huggingfaceapikey.HuggingfaceAPIKey{
									Key: "foo2",
								},
								Location: path,
							},
						},
					},
				},
				{
					name:       "non-200 status code",
					statusCode: http.StatusUnauthorized, // 401 Unauthorized
					input: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret:   huggingfaceapikey.HuggingfaceAPIKey{Key: "foo3"},
								Location: path,
							},
						},
					},
					want: inventory.Inventory{
						Secrets: []*inventory.Secret{
							{
								Secret: huggingfaceapikey.HuggingfaceAPIKey{
									Key: "foo3",
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
					// Mock Hugging Face API server responding with the desired role and fineGrainedScope
					ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						if r.URL.Path != "/api/whoami-v2" {
							http.NotFound(w, r)
							return
						}
						// Return the status code defined in the test case
						if sc.statusCode != 0 && sc.statusCode != http.StatusOK {
							w.WriteHeader(sc.statusCode)
							return
						}

						w.Header().Set("Content-Type", "application/json")
						if _, ok := sc.respBody.(string); ok {
							_, err := w.Write([]byte(sc.respBody.(string)))
							if err != nil {
								return
							}
							return
						}
						_ = json.NewEncoder(w).Encode(sc.respBody)
					}))
					defer ts.Close()

					// Use enricher configured against the mock server
					enricher := huggingfacemeta.NewWithBaseURL(ts.URL)

					err := enricher.Enrich(t.Context(), nil, &sc.input)
					if !cmp.Equal(err, sc.wantErr, cmpopts.EquateErrors()) {
						t.Fatalf("Enrich() error: got %v, want %v\n", err, sc.wantErr)
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
