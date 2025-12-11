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

package bitbucket_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/bitbucket"
)

var (
	validatorTestURL         = "https://user:password@bitbucket.org/workspace/project-repo.git"
	validatorTokenURL        = "https://x-token-auth:token@bitbucket.org/workspace/project-repo.git"
	validatorTestBadCredsURL = "https://user:bad_password@bitbucket.org/workspace/project-repo.git"
	validatorTestBadRepoURL  = "https://x-token-auth:token@bitbucket.org/workspace/bad-project-repo.git"
)

type redirectTransport struct {
	url string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.URL.Host == "bitbucket.org" {

		newURL, err := url.Parse(t.url)
		if err != nil {
			return nil, err
		}
		req.URL.Scheme = newURL.Scheme
		req.URL.Host = newURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mockbitbucketHandler(t *testing.T, status int) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("r.Method = %s, want %s", r.Method, http.MethodGet)
		}
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Basic") {
			t.Errorf("should use basic auth")
		}
		w.WriteHeader(status)
		if status != 200 {
			_, _ = w.Write([]byte(`You may not have access to this repository or it no longer exists in this workspace. If you think this repository exists and you have access, make sure you are authenticated.`))
			return
		}
		_, _ = w.Write([]byte(`001d# service=git-upload-pack0000014c4ee0de35abfc4b647af50b5f3fbe54641b9cd69f HEADmulti_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed allow-tip-sha1-in-want allow-reachable-sha1-in-want no-done symref=HEAD:refs/heads/main filter object-format=sha1 agent=git/2.51.0-Linux
003d4ee0de35abfc4b647af50b5f3fbe54641b9cd69f refs/heads/main
0000`))
	}
}

func TestValidator(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	cases := []struct {
		//nolint:containedctx
		ctx        context.Context
		name       string
		url        string
		httpStatus int
		want       veles.ValidationStatus
		wantErr    error
	}{
		{
			name:       "cancelled_context",
			url:        validatorTestURL,
			want:       veles.ValidationFailed,
			ctx:        cancelledContext,
			httpStatus: http.StatusOK,
			wantErr:    cmpopts.AnyError,
		},
		{
			name:       "valid_credentials",
			url:        validatorTestURL,
			httpStatus: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "valid_token",
			url:        validatorTokenURL,
			httpStatus: http.StatusOK,
			want:       veles.ValidationValid,
		},
		{
			name:       "invalid_creds",
			url:        validatorTestBadCredsURL,
			httpStatus: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "bad_repository",
			url:        validatorTestBadRepoURL,
			httpStatus: http.StatusUnauthorized,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context()
			}
			server := httptest.NewServer(mockbitbucketHandler(t, tt.httpStatus))
			defer server.Close()

			client := &http.Client{
				Transport: &redirectTransport{url: server.URL},
			}

			v := bitbucket.NewValidator()
			v.HTTPC = client

			got, err := v.Validate(tt.ctx, bitbucket.Credentials{FullURL: tt.url})

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("v.Validate() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
