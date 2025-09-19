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

package gcpoauth2_test

import (
	"context"
	"testing"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2"
)

func TestValidator_Validate_FormatValidation(t *testing.T) {
	validator := gcpoauth2.NewValidator()
	ctx := context.Background()

	tests := []struct {
		name     string
		secret   gcpoauth2.ClientCredentials
		expected veles.ValidationStatus
	}{
		{
			name: "valid client ID format only",
			secret: gcpoauth2.ClientCredentials{
				ClientID: "717762328687-iludtf96g1hinl76e4lc1b9a82g457nn.apps.googleusercontent.com",
			},
			expected: veles.ValidationValid,
		},
		{
			name: "invalid client ID format only",
			secret: gcpoauth2.ClientCredentials{
				ClientID: "invalid-format",
			},
			expected: veles.ValidationInvalid,
		},
		{
			name: "valid client secret format only",
			secret: gcpoauth2.ClientCredentials{
				ClientSecret: "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",
			},
			expected: veles.ValidationValid,
		},
		{
			name: "invalid client secret format only",
			secret: gcpoauth2.ClientCredentials{
				ClientSecret: "short",
			},
			expected: veles.ValidationInvalid,
		},
		{
			name: "valid ID format",
			secret: gcpoauth2.ClientCredentials{
				ID: "123456789012-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com",
			},
			expected: veles.ValidationValid,
		},
		{
			name: "invalid ID format",
			secret: gcpoauth2.ClientCredentials{
				ID: "invalid-id",
			},
			expected: veles.ValidationInvalid,
		},
		{
			name:     "empty credentials",
			secret:   gcpoauth2.ClientCredentials{},
			expected: veles.ValidationInvalid,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := validator.Validate(ctx, tt.secret)
			if err != nil {
				t.Errorf("Validate() error = %v, want nil", err)
				return
			}
			if status != tt.expected {
				t.Errorf("Validate() = %v, want %v", status, tt.expected)
			}
		})
	}
}

// Note: Full OAuth2 validation tests would require actual credentials or extensive mocking
// The format validation tests above cover the main validation logic for partial credentials
