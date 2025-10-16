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
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/osv-scalibr/veles"
)

const (
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	CodeAccessDenied          = "AccessDenied"
)

// Validator is a Veles Validator for Google Cloud Storage HMAC keys
type Validator struct {
	options s3.Options
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithEndpointResolver configures the s3.Client that the Validator uses.
func WithURL(url string) ValidatorOption {
	return func(v *Validator) {
		v.options.BaseEndpoint = &url
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
	client := s3.New(opts, ignoreAcceptEncodingOpt)

	_, err := client.HeadBucket(context.Background(), &s3.HeadBucketInput{
		Bucket: aws.String("test"),
	})
	if err != nil {
		notFound := &types.NotFound{}
		noSuchBucket := &types.NoSuchBucket{}
		if errors.As(err, &notFound) || errors.As(err, &noSuchBucket) {
			return veles.ValidationValid, nil
		}
		apiErr := &smithy.GenericAPIError{}
		if errors.As(err, &apiErr) {
			if apiErr.Code == CodeAccessDenied {
				return veles.ValidationValid, nil
			}
			if apiErr.Code == CodeSignatureDoesNotMatch {
				return veles.ValidationInvalid, nil
			}
		}
		return veles.ValidationFailed, fmt.Errorf("unknown error %w", err)
	}

	return veles.ValidationValid, nil
}
