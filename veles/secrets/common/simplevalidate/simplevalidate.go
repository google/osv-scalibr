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
	// The HTTP request method to send (e.g. http.MethodGet, http.MethodPost)
	HTTPMethod string
	// HTTP headers to set in the query based on the secret.
	HTTPHeaders func(S) map[string]string
	// The body to set in the query based on the secret
	Body func(S) string
	// Status codes that should result in a "ValidationValid" validation result.
	ValidResponseCodes []int
	// Status codes that should result in a "ValidationInvalid" validation result.
	InvalidResponseCodes []int
	// Additional custom validation logic to perform on the response body. Will run if none of the
	// status codes from ValidResponseCodes and InvalidResponseCodes have been found.
	StatusFromResponseBody func(body []byte) (veles.ValidationStatus, error)
	httpC                  *http.Client
}

// Option configures a Validator when creating it.
type Option[S veles.Secret] func(*Validator[S])

// New creates a new Validator with the given options.
func New[S veles.Secret](opts ...Option[S]) *Validator[S] {
	v := &Validator[S]{
		httpC: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// WithClient configures the HTTP client this validator should use. Defaults to http.DefaultClient.
func WithClient[S veles.Secret](c *http.Client) Option[S] {
	return func(v *Validator[S]) {
		v.httpC = c
	}
}

// WithEndpoint configures the API endpoint to query.
func WithEndpoint[S veles.Secret](e string) Option[S] {
	return func(v *Validator[S]) {
		v.Endpoint = e
	}
}

// WithHTTPMethod configures HTTP request method to send (e.g. http.MethodGet, http.MethodPost)
func WithHTTPMethod[S veles.Secret](m string) Option[S] {
	return func(v *Validator[S]) {
		v.HTTPMethod = m
	}
}

// WithHTTPHeaders configures HTTP headers to set in the query based on the secret.
func WithHTTPHeaders[S veles.Secret](h func(S) map[string]string) Option[S] {
	return func(v *Validator[S]) {
		v.HTTPHeaders = h
	}
}

// WithBody configures the request body to set in the query based on the secret.
func WithBody[S veles.Secret](b func(S) string) Option[S] {
	return func(v *Validator[S]) {
		v.Body = b
	}
}

// WithValidResponseCodes configures status codes that should result in a
// "ValidationValid" validation result.
func WithValidResponseCodes[S veles.Secret](r []int) Option[S] {
	return func(v *Validator[S]) {
		v.ValidResponseCodes = r
	}
}

// WithInvalidResponseCodes configures status codes that should result in a
// "ValidationInvalid" validation result.
func WithInvalidResponseCodes[S veles.Secret](r []int) Option[S] {
	return func(v *Validator[S]) {
		v.InvalidResponseCodes = r
	}
}

// WithStatusFromResponseBody configures the function that performs additional custom validation
// on the response body. This will only run if none of the status codes from ValidResponseCodes
// and InvalidResponseCodes have been found.
func WithStatusFromResponseBody[S veles.Secret](f func(body []byte) (veles.ValidationStatus, error)) Option[S] {
	return func(v *Validator[S]) {
		v.StatusFromResponseBody = f
	}
}

// Validate validates a secret with a simple HTTP request.
func (v *Validator[S]) Validate(ctx context.Context, secret S) (veles.ValidationStatus, error) {
	var reqBodyReader io.Reader
	if v.Body != nil {
		reqBody := v.Body(secret)
		if len(reqBody) > 0 {
			reqBodyReader = strings.NewReader(reqBody)
		}
	}
	req, err := http.NewRequestWithContext(ctx, v.HTTPMethod, v.Endpoint, reqBodyReader)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}
	if v.HTTPHeaders != nil {
		for key, val := range v.HTTPHeaders(secret) {
			req.Header.Set(key, val)
		}
	}
	res, err := v.httpC.Do(req)
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

	body, err := io.ReadAll(res.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to read response body: %w", err)
	}
	if v.StatusFromResponseBody != nil {
		return v.StatusFromResponseBody(body)
	}

	return veles.ValidationFailed, fmt.Errorf("unexpected HTTP status: %d", res.StatusCode)
}
