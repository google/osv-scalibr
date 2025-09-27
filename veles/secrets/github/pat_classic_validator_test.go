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

package github_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github"
	"github.com/google/osv-scalibr/veles/secrets/github/mockgithub"
)

const (
	classicPATValidatorKey = `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`
)

func TestClassicPATValidator(t *testing.T) {
	cancelledContext, cancel := context.WithCancel(t.Context())
	cancel()

	mockGithubServer := func(code int) *httptest.Server {
		return mockgithub.Server(
			t, "/user", code,
			classicPATValidatorKey,
		)
	}

	cases := []struct {
		name    string
		token   string
		server  *httptest.Server
		want    veles.ValidationStatus
		wantErr error
		//nolint:containedctx
		ctx context.Context
	}{
		{
			name:    "cancelled_context",
			ctx:     cancelledContext,
			server:  mockGithubServer(http.StatusOK),
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			name:   "valid_classic_key",
			token:  classicPATValidatorKey,
			server: mockGithubServer(http.StatusOK),
			want:   veles.ValidationValid,
		},
		{
			name:   "invalid_key_unauthorized",
			token:  "random_string",
			server: mockGithubServer(http.StatusUnauthorized),
			want:   veles.ValidationInvalid,
		},
		{
			name:   "server_error",
			server: mockGithubServer(http.StatusInternalServerError),
			want:   veles.ValidationFailed,
		},
		{
			name:   "bad_gateway",
			server: mockGithubServer(http.StatusBadGateway),
			want:   veles.ValidationFailed,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if tt.ctx == nil {
				tt.ctx = t.Context() //nolint:fatcontext
			}

			// Create a client with custom transport
			client := &http.Client{
				Transport: mockgithub.Transport(tt.server),
			}

			// Create a validator with a mock client
			validator := github.NewClassicPATValidator(
				github.ClassicPATWithClient(client),
			)

			// Create a test key
			key := github.ClassicPersonalAccessToken{Token: tt.token}

			// Test validation
			got, err := validator.Validate(tt.ctx, key)

			if !cmp.Equal(tt.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tt.wantErr)
			}

			if tt.want != got {
				t.Errorf("Validate(): got: %v, want: %v", got, tt.want)
			}
		})
	}
}
