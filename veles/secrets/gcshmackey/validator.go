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
	"errors"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/google/osv-scalibr/veles"
)

const (
	// CodeSignatureDoesNotMatch is returned by GCS if a request and the signature don't match
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	// CodeAccessDenied is returned by GCS if the user doesn't have access to a resource
	CodeAccessDenied = "AccessDenied"
)

// Validator is a Veles Validator for Google Cloud Storage HMAC keys
type Validator struct {
	options s3.Options
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithURL configures the URL that the Validator uses.
func WithURL(url string) ValidatorOption {
	return func(v *Validator) {
		v.options.BaseEndpoint = &url
	}
}

// WithSigner configures s3.HTTPSignerV4 that the Validator uses.
func WithSigner(signer s3.HTTPSignerV4) ValidatorOption {
	return func(v *Validator) {
		v.options.HTTPSignerV4 = signer
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		options: s3.Options{
			Region:       "auto",
			UsePathStyle: true,
			BaseEndpoint: aws.String("https://storage.googleapis.com"),
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Google Cloud Storage HMAC key
func (v *Validator) Validate(ctx context.Context, key HMACKey) (veles.ValidationStatus, error) {
	opts := v.options.Copy()
	opts.Credentials = credentials.NewStaticCredentialsProvider(key.AccessID, key.Secret, "")
	client := s3.New(opts, patchForGCSOpt)

	_, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) {
			// If the access is denied it means that
			// the key is valid but lacks permission for ListBuckets.
			if apiErr.ErrorCode() == CodeAccessDenied {
				return veles.ValidationValid, nil
			}
			if apiErr.ErrorCode() == CodeSignatureDoesNotMatch {
				return veles.ValidationInvalid, nil
			}
		}
		return veles.ValidationFailed, fmt.Errorf("unknown error %w", err)
	}

	return veles.ValidationValid, nil
}
