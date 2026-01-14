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

package codecatalyst_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecatalyst"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/mockserver"
)

var (
	validatorTestURL         = "https://user:pat@git.region.codecatalyst.aws/v1/space/project/repo"
	validatorTestBadCredsURL = "https://user:bad_pat@git.region.codecatalyst.aws/v1/space/project/repo"
	validatorTestBadRepoURL  = "https://user:pat@git.region.codecatalyst.aws/v1/space/project/bad-repo"
	badHostURL               = "https://user:pat@bad-host.com/v1/space/project/bad-repo"
)

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
			name:    "bad_host",
			url:     badHostURL,
			wantErr: cmpopts.AnyError,
			want:    veles.ValidationFailed,
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
			httpStatus: http.StatusBadRequest,
			want:       veles.ValidationInvalid,
		},
		{
			name:       "bad_repository",
			url:        validatorTestBadRepoURL,
			httpStatus: http.StatusBadRequest,
			want:       veles.ValidationInvalid,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context()
			}
			server := httptest.NewServer(mockserver.GitHandler(t, tt.httpStatus))
			defer server.Close()

			client := &http.Client{
				Transport: &mockserver.Transport{
					URL: server.URL,
				},
			}

			v := codecatalyst.NewValidator()
			v.HTTPC = client

			got, err := v.Validate(tt.ctx, codecatalyst.Credentials{FullURL: tt.url})

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("v.Validate() returned diff (-want +got):\n%s", diff)
			}
		})
	}
}
