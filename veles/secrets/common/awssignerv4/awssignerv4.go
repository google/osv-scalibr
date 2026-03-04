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

// Package awssignerv4 provides an implementation of AWS Signature Version 4 signing.
// It allows signing HTTP requests using AWS credentials
package awssignerv4

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
)

// Signer provides AWS Signature Version 4 signing for HTTP requests.
//
// ref: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
type Signer struct {
	Config
}

// Config used to create a Signer.
type Config struct {
	Service       string // AWS service name (e.g. "s3")
	Region        string // AWS region (e.g., "us-east-1")
	Now           func() time.Time
	UUID          func() string
	SignedHeaders []string
}

// New creates a new Signer using the given config.
func New(cfg Config) *Signer {
	s := &Signer{
		Config: cfg,
	}
	if s.Now == nil {
		s.Now = time.Now().UTC
	}
	if s.UUID == nil {
		s.UUID = func() string { return uuid.New().String() }
	}
	return s
}

// Sign applies AWS Signature Version 4 signing to an HTTP request.
//
//	Example usage:
//
//	s := signer.Signer{Service: "s3", Region: "us-east-1"}
//	req, _ := http.NewRequest("GET", "https://my-bucket.s3.amazonaws.com/my-object", nil)
//	err := s.Sign(req, "AKIAEXAMPLE", "secretkey123")
func (s *Signer) Sign(req *http.Request, accessID, secret string) error {
	now := s.Now()
	amzDate := now.Format("20060102T150405Z")
	date := now.Format("20060102")

	payload := ""
	if req.Body != nil {
		// read the body without disrupting it
		body, err := io.ReadAll(req.Body)
		if err != nil {
			_ = req.Body.Close()
		}
		payload = string(body)
		req.Body = io.NopCloser(bytes.NewReader(body))
	}

	payloadHash := sha256Hex(payload)

	// Mutate the request headers
	req.Header.Set("Amz-Sdk-Invocation-Id", s.UUID())
	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Amz-Date", amzDate)
	if len(payload) > 0 {
		req.Header.Set("Content-Length", strconv.Itoa(len(payload)))
	}

	var canonicalHeadersB strings.Builder
	for _, h := range s.SignedHeaders {
		v := req.Header.Get(h)
		if len(v) == 0 {
			return fmt.Errorf("header %q not found", h)
		}
		fmt.Fprintf(&canonicalHeadersB, "%s:%s\n", h, v)
	}
	canonicalHeaders := canonicalHeadersB.String()
	signedHeaders := strings.Join(s.SignedHeaders, ";")

	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.Path,
		req.URL.RawQuery, canonicalHeaders,
		signedHeaders, payloadHash,
	}, "\n")
	canonicalRequestHash := sha256Hex(canonicalRequest)

	// String to sign
	credentialScope := fmt.Sprintf("%s/%s/%s/aws4_request", date, s.Region, s.Service)
	stringToSign := strings.Join([]string{
		"AWS4-HMAC-SHA256", amzDate, credentialScope, canonicalRequestHash,
	}, "\n")

	// Signature
	signingKey := getSignatureKey(secret, date, s.Region, s.Service)
	signature := hex.EncodeToString(hmacSHA256(signingKey, stringToSign))

	authorizationHeader := fmt.Sprintf(
		"AWS4-HMAC-SHA256 Credential=%s/%s, SignedHeaders=%s, Signature=%s",
		accessID, credentialScope, signedHeaders, signature,
	)
	req.Header.Set("Authorization", authorizationHeader)
	return nil
}

func hmacSHA256(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

// SHA256 hash helper
func sha256Hex(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// Derive signing key
//
// ref: https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html#signing-key
func getSignatureKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}
