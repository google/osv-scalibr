// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package onepasswordkeys provides validation for 1Password Service Account Tokens.
package onepasswordkeys

import (
	"context"

	"github.com/1password/onepassword-sdk-go"
	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure the validator satisfies the interface at compile time.
	_ veles.Validator[OnePasswordServiceToken] = &ValidatorServiceToken{}
)

// ValidatorServiceToken validates 1Password Service Account Tokens.
type ValidatorServiceToken struct{}

// NewServiceTokenValidator creates a new ValidatorServiceToken.
func NewServiceTokenValidator() *ValidatorServiceToken {
	return &ValidatorServiceToken{}
}

// Validate checks whether the given OnePasswordServiceToken is valid.
func (v *ValidatorServiceToken) Validate(ctx context.Context, key OnePasswordServiceToken) (veles.ValidationStatus, error) {
	// We rely on the SDK's validation : https://github.com/1Password/onepassword-sdk-go
	client, err := onepassword.NewClient(
		ctx,
		onepassword.WithServiceAccountToken(key.Key),
		onepassword.WithIntegrationInfo("OSV-Scalibr", "0.1.0"),
	)
	if err != nil {
		// If the token is invalid, the NewClient function will return an error.
		return veles.ValidationInvalid, err
	}
	// To avoid the unused lint error
	_, _ = client.Vaults().List(ctx)

	return veles.ValidationValid, nil
}
