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

package huggingfaceapikey

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates Huggingface API keys via the Huggingface API endpoint.
type Validator struct {
	httpC *http.Client
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client that the Validator uses.
//
// By default, it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given HuggingfaceAPIKey is valid.
//
// It performs a GET request to the Huggingface chat completions endpoint
// using the API key in the Authorization header. If the request returns
// HTTP 200, the key is considered valid. If 401 Unauthorized, the key
// is invalid. Other errors return ValidationFailed.
func (v *Validator) Validate(ctx context.Context, key HuggingfaceAPIKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://huggingface.co/api/whoami-v2", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Key)

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP GET failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil
	case http.StatusUnauthorized:
		return veles.ValidationInvalid, nil
	case http.StatusTooManyRequests:
		return veles.ValidationValid, nil
	case http.StatusInternalServerError:
		return veles.ValidationFailed, fmt.Errorf("unexpected server-side error: %d", res.StatusCode)
	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
	}
}
