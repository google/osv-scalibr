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

package alibabaaccesskey

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

const (
	stsEndpoint = "https://sts.aliyuncs.com/"
	apiVersion  = "2015-04-01"

	// Common Alibaba Cloud API error codes for invalid credentials
	CodeInvalidAccessKeyId = "InvalidAccessKeyId.NotFound"
	CodeSignatureMismatch  = "SignatureDoesNotMatch"
	CodeNoPermission       = "NoPermission"
)

// Validator is a Veles Validator for Alibaba Cloud Access Keys
type Validator struct {
	client *http.Client
}

// NewValidator creates a new Validator with default settings.
func NewValidator() *Validator {
	return &Validator{
		client: http.DefaultClient,
	}
}

// SetHTTPClient configures the http.Client that the Validator uses.
func (v *Validator) SetHTTPClient(cli *http.Client) {
	v.client = cli
}

// Validate checks whether the given Alibaba Cloud access key and secret are valid
// using the STS GetCallerIdentity API call.
func (v *Validator) Validate(ctx context.Context, key *Credentials) (veles.ValidationStatus, error) {
	// 1. Prepare all required API parameters
	params := map[string]string{
		"Action":           "GetCallerIdentity",
		"Version":          apiVersion,
		"Format":           "JSON",
		"AccessKeyId":      key.AccessID,
		"SignatureMethod":  "HMAC-SHA256",
		"SignatureVersion": "1.0",
		"SignatureNonce":   generateNonce(),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}

	// 2. Generate the HMAC-SHA256 signature
	signature := signAlibabaRequest(http.MethodGet, params, key.Secret)
	params["Signature"] = signature

	// 3. Build the final request URL
	reqURL, err := url.Parse(stsEndpoint)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse endpoint: %w", err)
	}

	query := reqURL.Query()
	for k, val := range params {
		query.Set(k, val)
	}
	reqURL.RawQuery = query.Encode()

	// 4. Create and send the HTTP request
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL.String(), nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building request failed: %w", err)
	}
	req.Header.Set("User-Agent", "osv-scalibr")

	rsp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer rsp.Body.Close()

	// Intercept the raw body before parsing
	bodyBytes, _ := io.ReadAll(rsp.Body)

	// 5. Evaluate the HTTP Response
	if rsp.StatusCode == http.StatusOK {
		// Parse the identity from the success response
		var success struct {
			Arn string `json:"Arn"`
		}
		if err := json.Unmarshal(bodyBytes, &success); err == nil {
			// Logic to determine Root vs RAM and extract name
			if strings.HasSuffix(success.Arn, ":root") {
				key.IsRamUser = false
				key.PrincipalName = "root"
			} else {
				key.IsRamUser = true
				// Example: acs:ram::12345:user/saurabh-dev -> saurabh-dev
				parts := strings.Split(success.Arn, "/")
				if len(parts) > 1 {
					key.PrincipalName = parts[len(parts)-1]
				}
			}
		}
		return veles.ValidationValid, nil
	}

	// Parse the JSON error response
	type errorResponse struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}

	var errResp errorResponse
	if err := json.Unmarshal(bodyBytes, &errResp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse response body (status %d): %w", rsp.StatusCode, err)
	}

	switch errResp.Code {
	case CodeInvalidAccessKeyId, CodeSignatureMismatch:
		return veles.ValidationInvalid, nil
	case CodeNoPermission:
		return veles.ValidationValid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unknown API error code: %q - %s", errResp.Code, errResp.Message)
	}
}

// -- Helper Functions for Alibaba RPC Signature --

// signAlibabaRequest creates the HMAC-SHA256 signature required by Alibaba Cloud
func signAlibabaRequest(httpMethod string, params map[string]string, secret string) string {
	// Sort parameters by key
	var keys []string
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build canonicalized query string
	var canonicalizedQueryString strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalizedQueryString.WriteString("&")
		}
		canonicalizedQueryString.WriteString(percentEncode(k))
		canonicalizedQueryString.WriteString("=")
		canonicalizedQueryString.WriteString(percentEncode(params[k]))
	}

	// Build the string to sign
	stringToSign := httpMethod + "&%2F&" + percentEncode(canonicalizedQueryString.String())

	// Calculate HMAC-SHA256 (Note: Alibaba requires appending an ampersand to the secret)
	mac := hmac.New(sha256.New, []byte(secret+"&"))
	mac.Write([]byte(stringToSign))

	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// percentEncode implements Alibaba's specific URL encoding rules
func percentEncode(s string) string {
	res := url.QueryEscape(s)
	res = strings.ReplaceAll(res, "+", "%20")
	res = strings.ReplaceAll(res, "*", "%2A")
	res = strings.ReplaceAll(res, "%7E", "~")
	return res
}

func generateNonce() string {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano()) // fallback
	}
	return hex.EncodeToString(bytes)
}
