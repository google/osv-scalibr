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

// Package gcpoauth2token provides validation for GCP OAuth2 access tokens,
// against Google's real tokeninfo endpoint.
// This can be used to manually validate real tokens.
// Test tokens can be generated via: https://developers.google.com/oauthplayground/
//
// Note: Do not submit any real or test tokens.
// The tokens will eventually expire and become invalid, breaking continuous tests.

package gcpoauth2_manual_test

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2token"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		token   gcpoauth2token.GCPOAuth2AccessToken
		want    veles.ValidationStatus
		wantErr bool
	}{
		{
			name: "empty token",
			token: gcpoauth2token.GCPOAuth2AccessToken{
				Token: "",
			},
			want:    veles.ValidationFailed,
			wantErr: true,
		},
		// -- Example of a valid token. Replace with a real token for manual testing.
		// {
		// 	name: "valid token",
		// 	token: gcpoauth2token.GCPOAuth2AccessToken{
		// 		Token: "ya29.a0AQQ_BDTp8QsUMgcGoezG7A1XQ7wI-6FaupdtJGT35GmIbLNISfIe04DzUlZ7GyqcKMOtF4bF_TbSEj6zaFA46fmFR6qLC0clpF1WwDFMCH1c2uVjYcoiy4lLMtz3XGJuv8kc8DNRqM7WOM3j5wHL2xaUrR8vdn23WiLZcgn-JkgclDWDTGoMEjWwM9XlfrtMMnA_eywaCgYKAUQSARESFQHGX2MiQ5dy52dLBdjQOFwKVI0rWg0206",
		// 	},
		// 	want:    veles.ValidationValid,
		// 	wantErr: false,
		// },
		// -- Example of an expired token. Replace with a real token for manual testing.
		// {
		// 	name: "valid token",
		// 	token: gcpoauth2token.GCPOAuth2AccessToken{
		// 		Token: "ya29.a0AQQ_BDTp8QsUMgcGoezG7A1XQ7wI-6FaupdtJGT35GmIbLNISfIe04DzUlZ7GyqcKMOtF4bF_TbSEj6zaFA46fmFR6qLC0clpF1WwDFMCH1c2uVjYcoiy4lLMtz3XGJuv8kc8DNRqM7WOM3j5wHL2xaUrR8vdn23WiLZcgn-JkgclDWDTGoMEjWwM9XlfrtMMnA_eywaCgYKAUQSARESFQHGX2MiQ5dy52dLBdjQOFwKVI0rWg0206",
		// 	},
		// 	want:    veles.ValidationInvalid,
		// 	wantErr: false,
		// },
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := veles.NewValidationEngine()
			veles.AddValidator(v, gcpoauth2token.NewValidator())
			got, err := v.Validate(context.Background(), tt.token)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Validate() got = %v, want %v", got, tt.want)
			}
		})
	}
}