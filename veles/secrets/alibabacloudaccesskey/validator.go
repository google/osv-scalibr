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

package alibabacloudaccesskey

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/uuid"
)

const (
	stsEndpoint      = "https://sts.aliyuncs.com/"
	signatureMethod  = "HMAC-SHA1"
	signatureVersion = "1.0"
	apiVersion       = "2015-04-01"
	apiFormat        = "JSON"
)

// Validator is a Veles Validator for Alibaba Cloud Access Key credentials.
type Validator struct {
	client *http.Client
	now    func() time.Time
	uuid   func() string
}

// SetHTTPClient configures the http.Client that the Validator uses.
func (v *Validator) SetHTTPClient(cli *http.Client) {
	v.client = cli
}

// NewValidator creates a new Validator.
func NewValidator() *Validator {
	return &Validator{
		client: http.DefaultClient,
		now:    func() time.Time { return time.Now().UTC() },
		uuid:   func() string { return uuid.New().String() },
	}
}

// Validate checks whether the given Alibaba Cloud Access Key credentials are valid
// using the STS GetCallerIdentity API call.
//
// ref: https://www.alibabacloud.com/help/en/ram/developer-reference/api-sts-2015-04-01-getcalleridentity
func (v *Validator) Validate(ctx context.Context, key Credentials) (veles.ValidationStatus, error) {
	params := map[string]string{
		"Action":           "GetCallerIdentity",
		"Format":           apiFormat,
		"Version":          apiVersion,
		"AccessKeyId":      key.AccessKeyID,
		"SignatureMethod":  signatureMethod,
		"SignatureNonce":   v.uuid(),
		"SignatureVersion": signatureVersion,
		"Timestamp":        v.now().Format("2006-01-02T15:04:05Z"),
	}

	signature := sign(params, key.AccessKeySecret)
	params["Signature"] = signature

	query := url.Values{}
	for k, val := range params {
		query.Set(k, val)
	}

	reqURL := stsEndpoint + "?" + query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("building request failed: %w", err)
	}
	req.Header.Set("User-Agent", "osv-scalibr")

	rsp, err := v.client.Do(req)
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("GET failed: %w", err)
	}
	defer rsp.Body.Close()

	if rsp.StatusCode == http.StatusOK {
		return veles.ValidationValid, nil
	}

	var errResp struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	if err := json.NewDecoder(rsp.Body).Decode(&errResp); err != nil {
		return veles.ValidationFailed, fmt.Errorf("failed to parse the response body: %w", err)
	}

	switch errResp.Code {
	case "SignatureDoesNotMatch", "InvalidAccessKeyId.NotFound", "InvalidAccessKeyId.Inactive":
		return veles.ValidationInvalid, nil
	case "Forbidden.AccessDenied":
		// Signature is valid, but the key lacks STS permissions.
		return veles.ValidationValid, nil
	default:
		return veles.ValidationFailed, fmt.Errorf("unknown error code: %q", errResp.Code)
	}
}

// sign creates an Alibaba Cloud RPC-style signature for the given parameters.
//
// ref: https://www.alibabacloud.com/help/en/sdk/product-overview/rpc-mechanism
func sign(params map[string]string, accessKeySecret string) string {
	// Sort parameter keys alphabetically.
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	// Build the canonicalized query string.
	var canonicalized strings.Builder
	for i, k := range keys {
		if i > 0 {
			canonicalized.WriteByte('&')
		}
		canonicalized.WriteString(percentEncode(k))
		canonicalized.WriteByte('=')
		canonicalized.WriteString(percentEncode(params[k]))
	}

	// Build the string to sign.
	stringToSign := "GET&" + percentEncode("/") + "&" + percentEncode(canonicalized.String())

	// Compute HMAC-SHA1 signature.
	mac := hmac.New(sha1.New, []byte(accessKeySecret+"&"))
	mac.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// percentEncode applies the Alibaba Cloud percent encoding rules.
// It is similar to url.QueryEscape but encodes spaces as %20 instead of +,
// and encodes * as %2A and ~ is not encoded.
func percentEncode(s string) string {
	encoded := url.QueryEscape(s)
	encoded = strings.ReplaceAll(encoded, "+", "%20")
	encoded = strings.ReplaceAll(encoded, "*", "%2A")
	encoded = strings.ReplaceAll(encoded, "%7E", "~")
	return encoded
}
