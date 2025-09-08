// Copyright 2025 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
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

const (
	// Stripe validation endpoint used for both SK and RK keys.
	stripeEndpoint = "https://api.stripe.com/v1/accounts"
)

//
// --- Stripe SK Validator (sk_test_, sk_live_) ---
//

// ValidatorSK validates Stripe SK keys (test + live).
// Logic: only a 200 OK response from Stripe means the key is valid.
type ValidatorSK struct {
	httpC *http.Client
}

// Ensure ValidatorSK implements veles.Validator.
var _ veles.Validator[veles.Secret] = &ValidatorSK{}

// ValidatorOptionSK allows configuration of ValidatorSK.
type ValidatorOptionSK func(*ValidatorSK)

// WithClientSK allows using a custom http.Client for ValidatorSK.
func WithClientSK(c *http.Client) ValidatorOptionSK {
	return func(v *ValidatorSK) {
		v.httpC = c
	}
}

// NewValidatorSK constructs a ValidatorSK.
func NewValidatorSK(opts ...ValidatorOptionSK) *ValidatorSK {
	v := &ValidatorSK{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate performs an API call using the SK key.
// - 200 OK → ValidationValid
// - Any other response → ValidationInvalid
func (v *ValidatorSK) Validate(ctx context.Context, s veles.Secret) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.SetBasicAuth(s.(interface{ GetKey() string }).GetKey(), "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", stripeEndpoint, err)
	}
	defer res.Body.Close()

	if res.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}
	return veles.ValidationInvalid, nil
}

//
// --- Stripe RK Validator (rk_test_, rk_live_) ---
//

// ValidatorRK validates Stripe RK keys (test + live).
// Logic:
//   - 200 OK → ValidationValid
//   - 403 Forbidden with "does not have the required permissions" in the error message → ValidationValid
//   - Anything else → ValidationInvalid
type ValidatorRK struct {
	httpC *http.Client
}

// Ensure ValidatorRK implements veles.Validator.
var _ veles.Validator[veles.Secret] = &ValidatorRK{}

// ValidatorOptionRK allows configuration of ValidatorRK.
type ValidatorOptionRK func(*ValidatorRK)

// WithClientRK allows using a custom http.Client for ValidatorRK.
func WithClientRK(c *http.Client) ValidatorOptionRK {
	return func(v *ValidatorRK) {
		v.httpC = c
	}
}

// NewValidatorRK constructs a ValidatorRK.
func NewValidatorRK(opts ...ValidatorOptionRK) *ValidatorRK {
	v := &ValidatorRK{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// rkErrorResponse models the JSON body returned on a 403 error.
type rkErrorResponse struct {
	Error struct {
		Message string `json:"message"`
	} `json:"error"`
}

// Validate performs an API call using the RK key.
// - 200 OK → ValidationValid
// - 403 with "does not have the required permissions" → ValidationValid
// - Any other response → ValidationInvalid
func (v *ValidatorRK) Validate(ctx context.Context, s veles.Secret) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, stripeEndpoint, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.SetBasicAuth(s.(interface{ GetKey() string }).GetKey(), "")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", stripeEndpoint, err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil

	case http.StatusForbidden:
		var resp rkErrorResponse
		if err := json.NewDecoder(res.Body).Decode(&resp); err != nil {
			return veles.ValidationFailed, fmt.Errorf("unable to parse 403 response: %w", err)
		}
		if strings.Contains(resp.Error.Message, "does not have the required permissions") {
			return veles.ValidationValid, nil
		}
		return veles.ValidationInvalid, nil

	default:
		return veles.ValidationInvalid, nil
	}
}
