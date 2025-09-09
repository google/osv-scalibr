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

package stripeapikey

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

const stripeEndpoint = "https://api.stripe.com/v1/accounts"

//
// --- Core SK validator (shared logic) ---
//

// ValidatorSK validates Stripe SK (Secret) keys (sk_test_, sk_live_).
// Logic:
//   - Send GET /v1/accounts using the provided key as Basic Auth.
//   - A key is considered valid ONLY if Stripe responds with HTTP 200.
//   - 5xx responses mean Stripe service issues → treat as "failed validation".
//   - All other status codes (mainly 4xx) mean the key is invalid.
type ValidatorSK struct {
	httpC *http.Client
}

// ValidatorOptionSK configures ValidatorSK (e.g., allows injecting custom http.Client).
type ValidatorOptionSK func(*ValidatorSK)

// WithClientSK allows injecting a custom http.Client into ValidatorSK.
// Useful for mocking/testing or customizing transport.
func WithClientSK(c *http.Client) ValidatorOptionSK {
	return func(v *ValidatorSK) { v.httpC = c }
}

// NewValidatorSK constructs a ValidatorSK with optional configuration.
func NewValidatorSK(opts ...ValidatorOptionSK) *ValidatorSK {
	v := &ValidatorSK{httpC: http.DefaultClient}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// validateKey checks if a given SK key is valid against Stripe’s /accounts API.
func (v *ValidatorSK) validateKey(
	ctx context.Context,
	key string,
) (veles.ValidationStatus, error) {
	// Build request to Stripe API
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, stripeEndpoint, nil,
	)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(key, "") // Use key as Basic Auth

	// Send request
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("http get: %w", err)
	}
	defer res.Body.Close()

	// Decision logic based on response status
	switch {
	case res.StatusCode == http.StatusOK:
		// Key is valid
		return veles.ValidationValid, nil
	case res.StatusCode >= 500:
		// Server-side error on Stripe side → retry later
		return veles.ValidationFailed, nil
	default:
		// 4xx errors (unauthorized, forbidden, etc.) → key invalid
		return veles.ValidationInvalid, nil
	}
}

//
// --- Core RK validator (shared logic) ---
//

// ValidatorRK validates Stripe Restricted (RK) keys (rk_test_, rk_live_).
// Logic:
//   - HTTP 200 → valid (unrestricted access).
//   - HTTP 403 with message "does not have the required permissions" → valid,
//     because restricted keys can still be active but scoped.
//   - HTTP 5xx → failed validation (Stripe service issue).
//   - Anything else → invalid.
type ValidatorRK struct {
	httpC *http.Client
}

// ValidatorOptionRK configures ValidatorRK.
type ValidatorOptionRK func(*ValidatorRK)

// WithClientRK allows injecting a custom http.Client.
func WithClientRK(c *http.Client) ValidatorOptionRK {
	return func(v *ValidatorRK) { v.httpC = c }
}

// NewValidatorRK constructs a ValidatorRK with optional configuration.
func NewValidatorRK(opts ...ValidatorOptionRK) *ValidatorRK {
	v := &ValidatorRK{httpC: http.DefaultClient}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// rkErrorResponse represents the JSON error structure returned by Stripe.
type rkErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// validateKey checks if a given RK key is valid against Stripe’s /accounts API.
func (v *ValidatorRK) validateKey(
	ctx context.Context,
	key string,
) (veles.ValidationStatus, error) {
	// Build request to Stripe API
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, stripeEndpoint, nil,
	)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(key, "")

	// Send request
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("http get: %w", err)
	}
	defer res.Body.Close()

	// Decision logic based on response
	switch {
	case res.StatusCode == http.StatusOK:
		// Key is valid and unrestricted
		return veles.ValidationValid, nil
	case res.StatusCode == http.StatusForbidden:
		// Could still be a valid restricted key
		var resp rkErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return veles.ValidationFailed,
				fmt.Errorf("parse 403: %w", err)
		}
		// Stripe explicitly indicates the key is valid but scoped
		if strings.Contains(
			resp.Error.Message,
			"does not have the required permissions",
		) {
			return veles.ValidationValid, nil
		}
		// Other 403 → invalid key
		return veles.ValidationInvalid, nil
	case res.StatusCode >= 500:
		// Stripe-side issue, not key-related
		return veles.ValidationFailed, nil
	default:
		// Other 4xx → invalid
		return veles.ValidationInvalid, nil
	}
}

//
// --- Typed Adapters (4 validators exposed) ---
//
// These adapters expose strongly typed validators for different
// Stripe key categories (test/live, SK/RK).
// Each wraps the shared core validator logic but enforces type safety.
//

// ValidatorSKTest validates StripeSKTestKey.
type ValidatorSKTest struct{ core *ValidatorSK }

// Validate runs validation on StripeSKTestKey.
func (v *ValidatorSKTest) Validate(
	ctx context.Context,
	s StripeSKTestKey,
) (veles.ValidationStatus, error) {
	return v.core.validateKey(ctx, s.Key)
}

// NewValidatorSKTest creates a Validator for StripeSKTestKey.
func NewValidatorSKTest(opts ...ValidatorOptionSK) *ValidatorSKTest {
	return &ValidatorSKTest{core: NewValidatorSK(opts...)}
}

// ValidatorSKLive validates StripeSKLiveKey.
type ValidatorSKLive struct{ core *ValidatorSK }

// Validate runs validation on StripeSKLiveKey.
func (v *ValidatorSKLive) Validate(
	ctx context.Context,
	s StripeSKLiveKey,
) (veles.ValidationStatus, error) {
	return v.core.validateKey(ctx, s.Key)
}

// NewValidatorSKLive creates a Validator for StripeSKLiveKey.
func NewValidatorSKLive(opts ...ValidatorOptionSK) *ValidatorSKLive {
	return &ValidatorSKLive{core: NewValidatorSK(opts...)}
}

// ValidatorRKTest validates StripeRKTestKey.
type ValidatorRKTest struct{ core *ValidatorRK }

// Validate runs validation on StripeRKTestKey.
func (v *ValidatorRKTest) Validate(
	ctx context.Context,
	s StripeRKTestKey,
) (veles.ValidationStatus, error) {
	return v.core.validateKey(ctx, s.Key)
}

// NewValidatorRKTest creates a Validator for StripeRKTestKey.
func NewValidatorRKTest(opts ...ValidatorOptionRK) *ValidatorRKTest {
	return &ValidatorRKTest{core: NewValidatorRK(opts...)}
}

// ValidatorRKLive validates StripeRKLiveKey.
type ValidatorRKLive struct{ core *ValidatorRK }

// Validate runs validation on StripeRKLiveKey.
func (v *ValidatorRKLive) Validate(
	ctx context.Context,
	s StripeRKLiveKey,
) (veles.ValidationStatus, error) {
	return v.core.validateKey(ctx, s.Key)
}

// NewValidatorRKLive creates a Validator for StripeRKLiveKey.
func NewValidatorRKLive(opts ...ValidatorOptionRK) *ValidatorRKLive {
	return &ValidatorRKLive{core: NewValidatorRK(opts...)}
}

// --- Compile-time assertions ---
//
// These ensure that all validators correctly implement the
// veles.Validator<T> interface at compile time.
var (
	_ veles.Validator[StripeSKTestKey] = &ValidatorSKTest{}
	_ veles.Validator[StripeSKLiveKey] = &ValidatorSKLive{}
	_ veles.Validator[StripeRKTestKey] = &ValidatorRKTest{}
	_ veles.Validator[StripeRKLiveKey] = &ValidatorRKLive{}
)
