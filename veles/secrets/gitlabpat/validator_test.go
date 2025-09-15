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

package gitlabpat_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
)

const validatorTestPat = "glpat-f4eFH_HGFDSPljX2t2eWBm3h3bp1ORR5116d1w.01.120reoret"

type redirectTransport struct {
	redirectTo     string
	hostToRedirect string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == t.hostToRedirect {
		newURL, err := url.Parse(t.redirectTo)
		if err != nil {
			return nil, err
		}
		req.URL.Scheme = newURL.Scheme
		req.URL.Host = newURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mockGitlabHandler(t *testing.T, expectedPAT string, status int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if got, want := r.Header.Get("PRIVATE-TOKEN"), expectedPAT; got != want { //nolint:canonicalheader
			t.Errorf("r.Header.Get('PRIVATE-TOKEN') = %s, want %s", got, want)
		}
		if r.Method != http.MethodGet {
			t.Errorf("r.Method = %s, want %s", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/api/v4/personal_access_tokens/self" {
			t.Errorf("r.URL.Path = %s, want /api/v4/personal_access_tokens/self", r.URL.Path)
		}
		w.WriteHeader(status)
	}
}

func TestValidator(t *testing.T) {
	cases := []struct {
		name       string
		pat        string
		httpStatus int
		want       veles.ValidationStatus
		wantErr    bool
	}{
		{
			name:       "valid pat",
			pat:        validatorTestPat,
			httpStatus: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid pat",
			pat:        "glpat-invalid",
			httpStatus: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "unexpected status code",
			pat:        validatorTestPat,
			httpStatus: http.StatusNotFound,
			want:       veles.ValidationFailed,
			wantErr:    true,
		},
		{
			name:       "empty pat",
			pat:        "",
			httpStatus: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(mockGitlabHandler(t, tc.pat, tc.httpStatus))
			defer server.Close()

			client := &http.Client{
				Transport: &redirectTransport{
					redirectTo:     server.URL,
					hostToRedirect: "gitlab.com",
				},
			}

			v := gitlabpat.NewValidator(gitlabpat.WithClient(client))

			ctx := context.Background()
			pat := gitlabpat.GitlabPAT{Pat: tc.pat}
			got, err := v.Validate(ctx, pat)

			if (err != nil) != tc.wantErr {
				t.Fatalf("v.Validate() error = %v, wantErr %v", err, tc.wantErr)
			}

			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("v.Validate() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
func TestValidator_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	client := &http.Client{
		Transport: &redirectTransport{
			redirectTo:     server.URL,
			hostToRedirect: "gitlab.com",
		},
	}
	validator := gitlabpat.NewValidator(
		gitlabpat.WithClient(client),
	)

	usernamePat := gitlabpat.GitlabPAT{Pat: validatorTestPat}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	got, err := validator.Validate(ctx, usernamePat)

	if !cmp.Equal(err, context.DeadlineExceeded, cmpopts.EquateErrors()) {
		t.Errorf("Validate() error = %v, want %v", err, context.DeadlineExceeded)
	}
	if got != veles.ValidationFailed {
		t.Errorf("Validate() = %v, want %v", got, veles.ValidationFailed)
	}
}
