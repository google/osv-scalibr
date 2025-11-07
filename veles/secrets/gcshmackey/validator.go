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

package gcshmackey

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/signerv4"
)

const (
	// CodeSignatureDoesNotMatch is returned by GCS if a request and the signature don't match
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	// CodeAccessDenied is returned by GCS if the user doesn't have access to a resource
	CodeAccessDenied = "AccessDenied"
)

// HTTPSignerV4 defines the interface for signing HTTP requests using
// the AWS Signature Version 4 signing process.
type HTTPSignerV4 interface {
	Sign(req *http.Request, accessKey, secretKey string) error
}

// Validator is a Veles Validator for Google Cloud Storage HMAC keys
type Validator struct {
	client *http.Client
	signer HTTPSignerV4
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithHTTPClient configures the http.Client that the Validator uses.
func WithHTTPClient(cli *http.Client) ValidatorOption {
	return func(v *Validator) {
		v.client = cli
	}
}

// WithSigner configures HTTPSignerV4 that the Validator uses.
func WithSigner(signer HTTPSignerV4) ValidatorOption {
	return func(v *Validator) {
		v.signer = signer
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		client: http.DefaultClient,
		signer: signerv4.New(signerv4.Config{
			Service: "s3", Region: "auto",
			SignedHeaders: []string{
				"amz-sdk-invocation-id", "amz-sdk-request", "host", "x-amz-content-sha256", "x-amz-date",
			},
		}),
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Google Cloud Storage HMAC key is valid
// using the ListBuckets api call
func (v *Validator) Validate(ctx context.Context, key HMACKey) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://storage.googleapis.com/", nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building failed: %w", err)
	}
	req.Header.Set("User-Agent", "osv-scalibr")
	req.Header.Set("Accept-Encoding", "gzip")

	if err := v.signer.Sign(req, key.AccessID, key.Secret); err != nil {
		return veles.ValidationFailed, fmt.Errorf("signing failed: %w", err)
	}

	rsp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("GET failed: %w", err)
	}

	// the credentials are valid and the resource is accessible
	if rsp.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse the response body: %w", err)
	}
	defer rsp.Body.Close()

	type errorResponse struct {
		Code string `xml:"Code"`
	}

	errResp := errorResponse{}
	if err := xml.Unmarshal(body, &errResp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse the response body: %w", err)
	}

	switch errResp.Code {
	case CodeSignatureDoesNotMatch:
		// Signature mismatch => credentials invalid
		return veles.ValidationInvalid, nil
	case CodeAccessDenied:
		// Signature valid, but account lacks access
		return veles.ValidationValid, nil
	default:
		// Unexpected error response
		return veles.ValidationFailed, fmt.Errorf("unknown error code: %q", errResp.Code)
	}
}
