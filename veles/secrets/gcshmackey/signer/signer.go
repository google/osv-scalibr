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

// Package signer provides an implementation of AWS Signature Version 4 signing.
// It allows signing HTTP requests using AWS credentials
package signer

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

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
func getSignatureKey(secret, date, region, service string) []byte {
	kDate := hmacSHA256([]byte("AWS4"+secret), date)
	kRegion := hmacSHA256(kDate, region)
	kService := hmacSHA256(kRegion, service)
	kSigning := hmacSHA256(kService, "aws4_request")
	return kSigning
}

// Signer provides AWS Signature Version 4 signing for HTTP requests.
type Signer struct {
	Service string // AWS service name (e.g. "s3")
	Region  string // AWS region (e.g., "us-east-1")
}

// Sign applies AWS Signature Version 4 signing to an HTTP request.
//
//	Example usage:
//
//	s := signer.Signer{Service: "s3", Region: "us-east-1"}
//	req, _ := http.NewRequest("GET", "https://my-bucket.s3.amazonaws.com/my-object", nil)
//	err := s.Sign(req, "AKIAEXAMPLE", "secretkey123")
func (s *Signer) Sign(req *http.Request, accessID, secret string) error {
	now := time.Now().UTC()
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
	invocationID := uuid.New().String()

	// Canonical request
	canonicalHeaders := fmt.Sprintf(
		"amz-sdk-invocation-id:%s\namz-sdk-request:attempt=1; max=3\nhost:%s\nx-amz-content-sha256:%s\nx-amz-date:%s\n",
		invocationID, req.Host, payloadHash, amzDate)
	signedHeaders := "amz-sdk-invocation-id;amz-sdk-request;host;x-amz-content-sha256;x-amz-date"

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

	// Mutate the request headers
	req.Header.Set("Amz-Sdk-Invocation-Id", invocationID)
	req.Header.Set("Amz-Sdk-Request", "attempt=1; max=3")
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Amz-Date", amzDate)
	req.Header.Set("Authorization", authorizationHeader)
	req.Header.Set("Accept-Encoding", "gzip")

	return nil
}
