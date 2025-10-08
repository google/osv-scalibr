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

package stripeapikeys

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

var (
	// Ensure constructors satisfy the interface at compile time.
	_ veles.Validator[StripeSecretKey]     = &SecretKeyValidator{}
	_ veles.Validator[StripeRestrictedKey] = &RestrictedKeyValidator{}
)

// Endpoints used for validation.
const (
	stripeAPIEndpoint = "https://api.stripe.com/v1/accounts"
)

// --- Stripe Secret Key Validator (SK) ---

// SecretKeyValidator validates Stripe Secret Keys (sk_live_...) using /v1/accounts.
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

// Validate checks whether the given StripeSecretKey is valid.
//
// It calls GET https://api.stripe.com/v1/accounts with Basic Auth.
// - 200 OK  -> authenticated and valid.
// - other   -> invalid.
func (v *SecretKeyValidator) Validate(ctx context.Context, key StripeSecretKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeAPIEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.SetBasicAuth(key.Key, "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", stripeAPIEndpoint, err)
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

// --- Stripe Restricted Key Validator (RK) ---

// RestrictedKeyValidator validates Stripe Restricted Keys (rk_live_...) using /v1/accounts.
type RestrictedKeyValidator struct {
	httpC *http.Client
}

// ValidatorOptionRestrictedKey configures a RestrictedKeyValidator when creating it via New.
type ValidatorOptionRestrictedKey func(*RestrictedKeyValidator)

// WithClientRestrictedKey configures the http.Client used by RestrictedKeyValidator.
//
// By default it uses http.DefaultClient.
func WithClientRestrictedKey(c *http.Client) ValidatorOptionRestrictedKey {
	return func(v *RestrictedKeyValidator) {
		v.httpC = c
	}
}

// NewRestrictedKeyValidator creates a new RestrictedKeyValidator with the given options.
func NewRestrictedKeyValidator(opts ...ValidatorOptionRestrictedKey) *RestrictedKeyValidator {
	v := &RestrictedKeyValidator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given StripeRestrictedKey is valid.
//
// It calls GET https://api.stripe.com/v1/accounts with Basic Auth.
// Restricted Keys are scoped to specific endpoints and permissions, so a 403
// from /v1/accounts does not necessarily mean the key is invalid.
// Possible outcomes:
//   - 200 OK       -> key has access to this endpoint and is valid.
//   - 403 Forbidden -> key is valid but lacks permission for this endpoint;
//     it may still work for other allowed endpoints.
//   - other         -> key is invalid.
func (v *RestrictedKeyValidator) Validate(ctx context.Context, key StripeRestrictedKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeAPIEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.SetBasicAuth(key.Key, "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", stripeAPIEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		// 200 OK => the key is valid and authenticated.
		return veles.ValidationValid, nil
	case http.StatusForbidden:
		// 403 Forbidden => considered valid (authenticated but not authorized for full access).
		return veles.ValidationValid, nil
	default:
		// Any other status code => invalid key.
		return veles.ValidationInvalid, nil
	}
}
