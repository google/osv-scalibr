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
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github"
	"github.com/google/osv-scalibr/veles/secrets/github/mockgithub"
)

const (
	fineGrainedPATValidatorKey = `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`
	classicPATValidatorKey     = `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`
)

func TestPATValidator(t *testing.T) {
	slowServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))
	defer slowServer.Close()

	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()

	mockGithubServer := func(code int) *httptest.Server {
		return mockgithub.Server(
			t, "/user", code,
			fineGrainedPATValidatorKey, classicPATValidatorKey,
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
			name:    "slow_server",
			ctx:     shortCtx,
			server:  slowServer,
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
			name:   "valid_finegrainded_key",
			token:  fineGrainedPATValidatorKey,
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
			validator := github.NewPATValidator(
				github.PATWithClient(client),
			)

			// Create a test key
			key := github.PersonalAccessToken{Token: tt.token}

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
