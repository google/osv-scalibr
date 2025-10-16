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

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/osv-scalibr/veles"
)

const (
	CodeSignatureDoesNotMatch = "SignatureDoesNotMatch"
	CodeInvalidArgument       = "InvalidArgument"
	CodeAccessDenied          = "AccessDenied"
)

// Validator is a Veles Validator for Google Cloud Storage HMAC keys
type Validator struct {
	client func(provider aws.CredentialsProvider) *s3.Client
}

// ValidatorOption configures a Validator when creating it via NewValidator.
type ValidatorOption func(*Validator)

// WithOptions configures the s3.Client that the Validator uses.
func WithOptions(opt s3.Options) ValidatorOption {
	return func(v *Validator) {
		v.client = func(provider aws.CredentialsProvider) *s3.Client {
			opt.Credentials = provider
			return s3.New(opt, ignoreAcceptEncodingOpt)
		}
	}
}

// NewValidator creates a new Validator with the given ValidatorOptions.
func NewValidator(opts ...ValidatorOption) *Validator {
	v := &Validator{
		client: func(provider aws.CredentialsProvider) *s3.Client {
			s3Opts := s3.Options{
				Region:           "auto",
				Credentials:      provider,
				EndpointResolver: s3.EndpointResolverFromURL("https://storage.googleapis.com"),
			}
			return s3.New(s3Opts, ignoreAcceptEncodingOpt)
		},
	}
	for _, opt := range opts {
		opt(v)
	}
	return v
}

// Validate checks whether the given Google Cloud Storage HMAC key
func (v *Validator) Validate(ctx context.Context, key HMACKey) (veles.ValidationStatus, error) {
	provider := credentials.NewStaticCredentialsProvider(key.AccessID, key.Secret, "")
	client := v.client(provider)

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
		return veles.ValidationFailed, nil
	}

	return veles.ValidationValid, nil
}
