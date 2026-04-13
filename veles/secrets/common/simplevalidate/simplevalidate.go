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
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/google/osv-scalibr/veles"
)

// Validator validates a secret of a given type by sending HTTP requests and
// checking the response status code.
// It implements veles.Validator.
type Validator[S veles.Secret] struct {
	// The API endpoint to query.
	Endpoint string
	// Function that constructs the endpoint for a given secret.
	// Exactly one of Endpoint or EndpointFunc must be provided.
	// The specificed endpoints get queried in order and the validation is considered valid
	// if either of them return a valid status.
	// If EndpointFunc returns an error, Validate returns ValidationFailed and the error.
	EndpointFunc func(S) (string, error)
	// The API endpoints to query.
	// The specificed endpoints get queried in order and the validation is considered valid
	// if either of them return a valid status.
	Endpoints []string
	// Function that constructs the endpoints for a given secret.
	// Exactly one of Endpoints or EndpointFuncs must be provided.
	// If EndpointsFunc returns an error, Validate returns ValidationFailed and the error.
	EndpointsFunc func(S) ([]string, error)
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

// Validate validates a secret with one or multiple HTTP requests.
func (v *Validator[S]) Validate(ctx context.Context, secret S) (veles.ValidationStatus, error) {
	if v.HTTPC == nil {
		v.HTTPC = http.DefaultClient
	}

	// Ensure exactly one endpoint configuration is provided.
	provided := 0
	if v.Endpoint != "" {
		provided++
	}
	if v.EndpointFunc != nil {
		provided++
	}
	if len(v.Endpoints) > 0 {
		provided++
	}
	if v.EndpointsFunc != nil {
		provided++
	}
	if provided != 1 || provided == 0 {
		return veles.ValidationFailed,
			errors.New("exactly one of Endpoint, EndpointFunc, Endpoints, or EndpointsFunc must be specified")
	}

	// Resolve endpoints
	var endpoints []string

	if v.Endpoint != "" {
		endpoints = []string{v.Endpoint}
	} else if v.EndpointFunc != nil {
		ep, err := v.EndpointFunc(secret)
		if err != nil {
			return veles.ValidationFailed, err
		}
		endpoints = []string{ep}
	} else if len(v.Endpoints) > 0 {
		endpoints = v.Endpoints
	} else if v.EndpointsFunc != nil {
		eps, err := v.EndpointsFunc(secret)
		if err != nil {
			return veles.ValidationFailed, err
		}
		if len(eps) == 0 {
			return veles.ValidationFailed, errors.New("EndpointsFunc returned no endpoints")
		}
		endpoints = eps
	}

	// Construct body once
	var reqBody string
	var err error
	if v.Body != nil {
		reqBody, err = v.Body(secret)
		if err != nil {
			return veles.ValidationFailed, err
		}
	}

	// sawInvalid is used to keep an eye on Invalid responses.
	// We return invalid if there was at least one invalid response and no valid ones.
	var sawInvalid bool

	var endpointErrors []error

	for _, endpoint := range endpoints {
		if ctx.Err() != nil {
			return veles.ValidationFailed, ctx.Err()
		}

		var reqBodyReader io.Reader
		if len(reqBody) > 0 {
			reqBodyReader = strings.NewReader(reqBody)
		}

		req, err := http.NewRequestWithContext(ctx, v.HTTPMethod, endpoint, reqBodyReader)
		if err != nil {
			return veles.ValidationFailed, fmt.Errorf("http.NewRequestWithContext: %w", err)
		}

		if v.HTTPHeaders != nil {
			for key, val := range v.HTTPHeaders(secret) {
				req.Header.Set(key, val)
			}
		}

		res, err := v.HTTPC.Do(req)
		if err != nil {
			if ctx.Err() != nil {
				return veles.ValidationFailed, err
			}
			endpointErrors = append(endpointErrors,
				fmt.Errorf("%s: HTTP request failed: %w", endpoint, err))
			continue
		}
		defer res.Body.Close()

		// Valid status
		if slices.Contains(v.ValidResponseCodes, res.StatusCode) {
			return veles.ValidationValid, nil
		}

		// Invalid status
		if slices.Contains(v.InvalidResponseCodes, res.StatusCode) {
			sawInvalid = true
			continue
		}

		// Custom body validation
		if v.StatusFromResponseBody != nil {
			status, bodyErr := v.StatusFromResponseBody(res.Body)

			if bodyErr != nil {
				endpointErrors = append(endpointErrors,
					fmt.Errorf("%s: body parse failed: %w", endpoint, bodyErr))
				continue
			}

			switch status {
			case veles.ValidationValid:
				return veles.ValidationValid, nil
			case veles.ValidationInvalid:
				sawInvalid = true
				continue
			case veles.ValidationFailed:
				continue
			}
		}

		// Unexpected status
		endpointErrors = append(endpointErrors,
			fmt.Errorf("%s: unexpected HTTP status %d", endpoint, res.StatusCode))
	}

	if sawInvalid {
		return veles.ValidationInvalid, nil
	}

	if len(endpointErrors) > 0 {
		return veles.ValidationFailed, errors.Join(endpointErrors...)
	}

	return veles.ValidationFailed,
		errors.New("no endpoint produced a definitive result")
}
