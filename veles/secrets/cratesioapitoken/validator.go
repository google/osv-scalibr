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

package cratesioapitoken

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates Crates.io API keys via the Crates.io API endpoint.
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

// Validate checks whether the given CratesIOAPItoken is valid.
//
// It performs a PUT request to the Crates.io API endpoint to add an owner to a non-existent crate
// using the API key in the Authorization header. Valid tokens return 404 Not Found,
// while invalid tokens return 401 Unauthorized.
func (v *Validator) Validate(ctx context.Context, key CratesIOAPItoken) (veles.ValidationStatus, error) {
	// Use a random crate name that is unlikely to exist
	randomBytes := make([]byte, 8)
	if _, err := rand.Read(randomBytes); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to generate random hex: %w", err)
	}
	randomCrateName := "osvscalibr" + hex.EncodeToString(randomBytes)
	randomUserName := "velesvalidationtestuser"

	// Prepare the JSON payload
	payload := map[string][]string{
		"users": {randomUserName},
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to marshal JSON payload: %w", err)
	}

	// Create the PUT request
	req, err := http.NewRequestWithContext(ctx, http.MethodPut,
		fmt.Sprintf("https://crates.io/api/v1/crates/%s/owners", randomCrateName), bytes.NewBuffer(jsonData))
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+key.Token)
	req.Header.Set("Content-Type", "application/json")

	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP PUT failed: %w", err)
	}
	defer res.Body.Close()

	switch res.StatusCode {
	case http.StatusNotFound: // crate doesn't exist, but the token is valid
		return veles.ValidationValid, nil
	case http.StatusForbidden: // invalid token
		return veles.ValidationInvalid, nil
	default:
		return veles.ValidationFailed, nil
	}
}
