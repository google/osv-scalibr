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

package paystacksecretkey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Validator[PaystackSecret] = &SecretKeyValidator{}
)

// Endpoint used for validation.
const (
	paystackAPIEndpoint = "https://api.paystack.co/customer"
)

// --- PayStack Secret Key Validator ---

// SecretKeyValidator validates PayStack Secret Keys (sk_...) using /customer.
type SecretKeyValidator struct {
	httpC *http.Client
}

// ValidatorOptionSecretKey configures a SecretKeyValidator when creating it via New.
type ValidatorOptionSecretKey func(*SecretKeyValidator)

// WithClientSecretKey configures the http.Client used by SecretKeyValidator.
//
// By default it uses http.DefaultClient.
func WithClientSecretKey(c *http.Client) ValidatorOptionSecretKey {
	return func(v *SecretKeyValidator) {
		v.httpC = c
	}
}

// NewSecretKeyValidator creates a new SecretKeyValidator with the given options.
func NewSecretKeyValidator(opts ...ValidatorOptionSecretKey) *SecretKeyValidator {
	v := &SecretKeyValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given PaystackSecret is valid.
//
// It calls GET https://api.paystack.co/customer with Bearer token.
// - 200 OK  -> authenticated and valid.
// - other   -> invalid.
func (v *SecretKeyValidator) Validate(ctx context.Context, key PaystackSecret) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, paystackAPIEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", paystackAPIEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 OK => the key is valid and authenticated.
		return veles.ValidationValid, nil
	default:
		// Any other status code => invalid key.
		return veles.ValidationInvalid, nil
	}
}
