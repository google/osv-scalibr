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

package gcpsak

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/osv-scalibr/veles"
)

const (
	defaultUniverse = "www.googleapis.com"
)

var _ veles.Validator[GCPSAK] = &Validator{}

// Validator is a Veles Validator for GCP service account keys.
// It uses GCP's robot metadata HTTP endpoint to try and fetch the public
// certificate for a given GCP SAK and use that for validation.
//
// TODO - b/409723520: Support universes beyond googleapis.com
type Validator struct {
	httpC           *http.Client
	defaultUniverse string
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithClient configures the http.Client that the Validator uses.
//
// By default it uses http.DefaultClient.
func WithClient(c *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.httpC = c
	}
}

// WithDefaultUniverse configures the Validator to use a different default
// universe other than "googleapis.com".
// This is useful for validating keys for a specific, known universe or for
// testing.
//
// Currently, the validator does not use the universe field from the key itself.
func WithDefaultUniverse(universe string) ValidatorOption {
	return func(v *Validator) {
		v.defaultUniverse = universe
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		httpC:           http.DefaultClient,
		defaultUniverse: defaultUniverse,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given GCPSAK is valid.
//
// It looks up the keys for the SAK's ServiceAccount from the GCP metadata
// server. If a corresponding public key can be found, it is used to validate
// the Signature.
func (v *Validator) Validate(ctx context.Context, sak GCPSAK) (veles.ValidationStatus, error) {
	clientX509CertURL := fmt.Sprintf("https://%s/robot/v1/metadata/x509/%s", v.defaultUniverse, url.PathEscape(sak.ServiceAccount))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, clientX509CertURL, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to create HTTP request: %w", err)
	}
	res, err := v.httpC.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q: %w", clientX509CertURL, err)
	}
	defer res.Body.Close()

	// If it's a 404, we know the corresponding service account does not exist
	// (anymore) or does not have any valid GCP SAK.
	if res.StatusCode == http.StatusNotFound {
		return veles.ValidationInvalid, nil
	}

	// If it's a 200, we can try to find the key's certificate and validate the
	// signature. Otherwise something must have gone wrong.
	if res.StatusCode != http.StatusOK {
		return veles.ValidationFailed, fmt.Errorf("unable to GET %q, got HTTP status %q", clientX509CertURL, res.Status)
	}

	certs := map[string]string{}
	if err := json.NewDecoder(res.Body).Decode(&certs); err != nil {
		return veles.ValidationFailed, fmt.Errorf("unable to parse certificates from %q: %w", clientX509CertURL, err)
	}
	cert, ok := certs[sak.PrivateKeyID]
	if !ok {
		return veles.ValidationInvalid, nil
	}
	valid, err := Valid(sak.Signature, cert)
	if err != nil {
		// This should never happen when using the real GCP metadata server.
		return veles.ValidationFailed, fmt.Errorf("unable to validate certificate from %q: %w", clientX509CertURL, err)
	}
	if valid {
		return veles.ValidationValid, nil
	}
	return veles.ValidationInvalid, nil
}
