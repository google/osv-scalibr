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

package token_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/github/token"
)

type fakeToken struct {
	token string
}

func (f fakeToken) GetToken() string {
	return f.token
}

func TestValidator(t *testing.T) {
	validator := token.NewCheckSumValidator[fakeToken]()

	cancelledContext, cancel := context.WithCancel(context.Background())
	cancel()

	cases := []struct {
		name    string
		token   fakeToken
		want    veles.ValidationStatus
		wantErr error
		//nolint:containedctx
		ctx context.Context
	}{
		{
			name:    "context cancelled",
			ctx:     cancelledContext,
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			name:  "example valid",
			token: fakeToken{"ghr_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG8fw"},
			want:  veles.ValidationValid,
		},
		{
			name:  "another example valid",
			token: fakeToken{"ghu_aGgfQsQ52sImE9zwWxKcjt2nhESfYG1U2FhX"},
			want:  veles.ValidationValid,
		},
		{
			name:    "invalid token",
			token:   fakeToken{"fjneiwnfewkfew"},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
		{
			name:    "invalid checksum",
			token:   fakeToken{"ghr_OWOCPzqKuy3J4w53QpkLfffjBUJSh5yLnFHj7wiyR0NDadVOcykNkoqhoYYXM1yy2sOpAu0lG1fw"},
			want:    veles.ValidationFailed,
			wantErr: cmpopts.AnyError,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if tc.ctx == nil {
				tc.ctx = context.Background()
			}

			got, err := validator.Validate(t.Context(), tc.token)
			if !cmp.Equal(tc.wantErr, err, cmpopts.EquateErrors()) {
				t.Fatalf("Validate() error: %v, want %v", err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("Validate() = %q, want %q", got, tc.want)
			}
		})
	}
}
