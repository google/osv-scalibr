// Copyright 2026 Google LLC
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

// Package simplevalidate contains a Validator for secrets that can be validated with
// simple HTTP queries and result code comparison.
package simplevalidate

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
	nv "github.com/google/osv-scalibr/veles/secrets/common/nvalidate"
)

// Validator validates a secret of a given type by sending HTTP requests and
// checking the response status code.
// It implements veles.Validator.
type Validator[S veles.Secret] struct {
	// The API endpoint to query.
	Endpoint string
	// Function that constructs the endpoint for a given secret.
	// Exactly one of Endpoint or EndpointFunc must be provided.
	// If EndpointFunc returns an error, Validate returns ValidationFailed and the error.
	EndpointFunc func(S) (string, error)
	// The HTTP request method to send (e.g. http.MethodGet, http.MethodPost)
	HTTPMethod string
	// HTTP headers to set in the query based on the secret.
	HTTPHeaders func(S) map[string]string
	// The body to set in the query based on the secret.
	// If Body returns an error, Validate returns ValidationFailed and the error.
	Body func(S) (string, error)
	// Status codes that should result in a "ValidationValid" validation result.
	ValidResponseCodes []int
	// Status codes that should result in a "ValidationInvalid" validation result.
	InvalidResponseCodes []int
	// Additional custom validation logic to perform on the response body. Will run if none of the
	// status codes from ValidResponseCodes and InvalidResponseCodes have been found.
	StatusFromResponseBody func(body io.Reader) (veles.ValidationStatus, error)
	// The HTTP client to use for the network queries. Uses http.DefaultClient if nil.
	HTTPC *http.Client
}

// Validate validates a secret with a simple HTTP request.
func (v *Validator[S]) Validate(ctx context.Context, secret S) (veles.ValidationStatus, error) {

	if (v.Endpoint == "" && v.EndpointFunc == nil) ||
		(v.Endpoint != "" && v.EndpointFunc != nil) {
		return veles.ValidationFailed, errors.New("exactly one of Endpoint or EndpointFunc must be specified")
	}

	nvValidator := &nv.Validator[S]{
		HTTPMethod:             v.HTTPMethod,
		HTTPHeaders:            v.HTTPHeaders,
		Body:                   v.Body,
		ValidResponseCodes:     v.ValidResponseCodes,
		InvalidResponseCodes:   v.InvalidResponseCodes,
		StatusFromResponseBody: v.StatusFromResponseBody,
		HTTPC:                  v.HTTPC,
	}

	if v.Endpoint != "" {
		nvValidator.Endpoints = []string{v.Endpoint}
	} else {
		nvValidator.EndpointFunc = func(s S) ([]string, error) {
			endpoint, err := v.EndpointFunc(s)
			if err != nil {
				return nil, err
			}
			if endpoint == "" {
				return nil, errors.New("EndpointFunc returned empty endpoint")
			}
			return []string{endpoint}, nil
		}
	}

	return nvValidator.Validate(ctx, secret)
}
