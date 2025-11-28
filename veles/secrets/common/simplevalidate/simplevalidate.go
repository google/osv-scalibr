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
	StatusFromResponseBody func(body io.Reader, secret S, req *http.Request) (veles.ValidationStatus, error)
	// The HTTP client to use for the network queries. Uses http.DefaultClient if nil.
	HTTPC *http.Client
}

// Validate validates a secret with a simple HTTP request.
func (v *Validator[S]) Validate(ctx context.Context, secret S) (veles.ValidationStatus, error) {
	if v.HTTPC == nil {
		v.HTTPC = http.DefaultClient
	}

	if (v.Endpoint == "" && v.EndpointFunc == nil) || (v.Endpoint != "" && v.EndpointFunc != nil) {
		return veles.ValidationFailed, errors.New("exactly one of Endpoint or EndpointFunc must be specified")
	}

	endpoint := v.Endpoint
	if v.EndpointFunc != nil {
		endpointURL, err := v.EndpointFunc(secret)
		if err != nil {
			return veles.ValidationFailed, err
		}
		endpoint = endpointURL
	}

	var reqBodyReader io.Reader
	if v.Body != nil {
		reqBody, err := v.Body(secret)
		if err != nil {
			return veles.ValidationFailed, err
		}
		if len(reqBody) > 0 {
			reqBodyReader = strings.NewReader(reqBody)
		}
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
		return veles.ValidationFailed, fmt.Errorf("HTTP %s failed: %w", v.HTTPMethod, err)
	}
	defer res.Body.Close()

	if slices.Contains(v.ValidResponseCodes, res.StatusCode) {
		return veles.ValidationValid, nil
	}
	if slices.Contains(v.InvalidResponseCodes, res.StatusCode) {
		return veles.ValidationInvalid, nil
	}

	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}
	if v.StatusFromResponseBody != nil {
		return v.StatusFromResponseBody(res.Body, secret, req)
	}

	return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
}
