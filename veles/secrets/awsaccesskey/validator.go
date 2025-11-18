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

package awsaccesskey

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/awssignerv4"
)

const (
	// CodeSignatureDoesNotMatch is returned by AWS if a request and the signature don't match
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	// CodeAccessDenied is returned by AWS if the user doesn't have access to a resource
	CodeAccessDenied = "AccessDenied"
)

// HTTPAwsSignerV4 defines the interface for signing HTTP requests using
// the AWS Signature Version 4 signing process.
type HTTPAwsSignerV4 interface {
	Sign(req *http.Request, accessKey, secretKey string) error
}

// Validator is a Veles Validator for Google Cloud Storage HMAC keys
type Validator struct {
	client *http.Client
	signer HTTPAwsSignerV4
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
func WithSigner(signer HTTPAwsSignerV4) ValidatorOption {
	return func(v *Validator) {
		v.signer = signer
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		client: http.DefaultClient,
		signer: awssignerv4.New(awssignerv4.Config{
			Service: "sts", Region: "us-east-1",
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

// Validate checks whether the given AWS access key and secret are valid
// using the GetCallerIdentity api call
func (v *Validator) Validate(ctx context.Context, key Credentials) (veles.ValidationStatus, error) {
	req, err := http.NewRequestWithContext(
		ctx, http.MethodPost,
		"https://sts.us-east-1.amazonaws.com/",
		io.NopCloser(strings.NewReader("Action=GetCallerIdentity&Version=2011-06-15")),
	)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building failed: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("User-Agent", "osv-scalibr")
	req.Header.Set("Host", "sts.us-east-1.amazonaws.com")
	req.Header.Set("Accept-Encoding", "gzip")

	if err := v.signer.Sign(req, key.AccessID, key.Secret); err != nil {
		return veles.ValidationFailed, fmt.Errorf("signing failed: %w", err)
	}

	rsp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("GET failed: %w", err)
	}

	if rsp.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}

	body, err := io.ReadAll(rsp.Body)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse the response body: %w", err)
	}
	defer rsp.Body.Close()

	type errorResponse struct {
		Error struct {
			Code string `xml:"Code"`
		} `xml:"Error"`
	}

	errResp := errorResponse{}
	if err := xml.Unmarshal(body, &errResp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse the response body: %w", err)
	}

	log.Println("errResp", errResp)
	switch errResp.Error.Code {
	case CodeSignatureDoesNotMatch:
		// Signature mismatch => credentials invalid
		return veles.ValidationInvalid, nil
	case CodeAccessDenied:
		// Signature valid, but account lacks access
		return veles.ValidationValid, nil
	default:
		// Unexpected error response
		return veles.ValidationFailed, fmt.Errorf("unknown error code: %q", errResp.Error.Code)
	}
}
