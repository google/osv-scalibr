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

// ValidatorSK validates Stripe SK keys (sk_test_, sk_live_).
// Rule: Only HTTP 200 means valid.
type ValidatorSK struct {
	httpC *http.Client
}

// ValidatorOptionSK configures ValidatorSK.
type ValidatorOptionSK func(*ValidatorSK)

// WithClientSK allows injecting a custom http.Client.
func WithClientSK(c *http.Client) ValidatorOptionSK {
	return func(v *ValidatorSK) { v.httpC = c }
}

// NewValidatorSK creates a new ValidatorSK.
func NewValidatorSK(opts ...ValidatorOptionSK) *ValidatorSK {
	v := &ValidatorSK{httpC: http.DefaultClient}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

func (v *ValidatorSK) validateKey(
	ctx context.Context,
	key string,
) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, stripeEndpoint, nil,
	)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(key, "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("http get: %w", err)
	}
	defer res.Body.Close()

	
	switch {
	case res.StatusCode == http.StatusOK:
		return veles.ValidationValid, nil
	case res.StatusCode >= 500:
		// Stripe service/server error
		return veles.ValidationFailed, nil
	default:
		// 4xx → invalid
		return veles.ValidationInvalid, nil
	}
}

//
// --- Core RK validator (shared logic) ---
//

// ValidatorRK validates Stripe RK keys (rk_test_, rk_live_).
// Rule:
//   200 → valid
//   403 with "does not have the required permissions" → valid (scoped)
//   else → invalid
type ValidatorRK struct {
	httpC *http.Client
}

// ValidatorOptionRK configures ValidatorRK.
type ValidatorOptionRK func(*ValidatorRK)

// WithClientRK allows injecting a custom http.Client.
func WithClientRK(c *http.Client) ValidatorOptionRK {
	return func(v *ValidatorRK) { v.httpC = c }
}

// NewValidatorRK creates a new ValidatorRK.
func NewValidatorRK(opts ...ValidatorOptionRK) *ValidatorRK {
	v := &ValidatorRK{httpC: http.DefaultClient}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

type rkErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

func (v *ValidatorRK) validateKey(
	ctx context.Context,
	key string,
) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, stripeEndpoint, nil,
	)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("create request: %w", err)
	}
	req.SetBasicAuth(key, "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed,
			fmt.Errorf("http get: %w", err)
	}
	defer res.Body.Close()

	switch {
	case res.StatusCode == http.StatusOK:
		return veles.ValidationValid, nil
	case res.StatusCode == http.StatusForbidden:
		var resp rkErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return veles.ValidationFailed,
				fmt.Errorf("parse 403: %w", err)
		}
		if strings.Contains(
			resp.Error.Message,
			"does not have the required permissions",
		) {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil
	case res.StatusCode >= 500:
		// Stripe service/server error
		return veles.ValidationFailed, nil
	default:
		return veles.ValidationInvalid, nil
	}
}

//
// --- Typed Adapters (4 validators exposed) ---
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

//
// --- Compile-time assertions ---
//

var (
	_ veles.Validator[StripeSKTestKey] = &ValidatorSKTest{}
	_ veles.Validator[StripeSKLiveKey] = &ValidatorSKLive{}
	_ veles.Validator[StripeRKTestKey] = &ValidatorRKTest{}
	_ veles.Validator[StripeRKLiveKey] = &ValidatorRKLive{}
)
