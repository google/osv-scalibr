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

package codecommit_test

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
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecommit"
)

var (
	validatorTestURL         = "https://user:token@git-codecommit.us-east-1.amazonaws.com/v1/repos/osv-scalibr-test"
	validatorTestBadCredsURL = "https://user:bad_token@git-codecommit.us-east-1.amazonaws.com/v1/repos/osv-scalibr-test"
	validatorTestBadRepoURL  = "https://user:token@git-codecommit.us-east-1.amazonaws.com/v1/repos/osv-scalibr-bad"
)

type redirectTransport struct {
	url string
}

func (t *redirectTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.HasSuffix(req.URL.Host, ".amazonaws.com") {

		newURL, err := url.Parse(t.url)
		if err != nil {
			return nil, err
		}
		req.URL.Scheme = newURL.Scheme
		req.URL.Host = newURL.Host
	}
	return http.DefaultTransport.RoundTrip(req)
}

func mockCodeCommitHandler(t *testing.T, status int) http.HandlerFunc {
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
		if status != http.StatusNotFound {
			_, _ = w.Write([]byte(`<RepositoryDoesNotExistException/>`))
			return
		}
		if status != http.StatusForbidden {
			_, _ = w.Write([]byte(`<AccessDeniedException>
  <Message>Invalid request</Message>
</AccessDeniedException>`))
			return
		}

		_, _ = w.Write([]byte(`001e# service=git-upload-pack
00000099c6cfbf1b4509f610801e5fff8b75623cd323f665 HEADmulti_ack_detailed shallow side-band-64k thin-pack allow-tip-sha1-in-want allow-reachable-sha1-in-want
003dc6cfbf1b4509f610801e5fff8b75623cd323f665 refs/heads/main
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
			name:       "invalid_creds",
			url:        validatorTestBadCredsURL,
			httpStatus: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "bad_repository",
			url:        validatorTestBadRepoURL,
			httpStatus: http.StatusForbidden,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context()
			}
			server := httptest.NewServer(mockCodeCommitHandler(t, tt.httpStatus))
			defer server.Close()

			client := &http.Client{
				Transport: &redirectTransport{url: server.URL},
			}

			v := codecommit.NewValidator()
			v.HTTPC = client

			got, err := v.Validate(tt.ctx, codecommit.Credentials{FullURL: tt.url})

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("v.Validate() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
