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

package hcp

import (
	"net/http"
	"net/url"

	sv "github.com/google/osv-scalibr/veles/secrets/common/simplevalidate"
)

// Defaults derived from public HCP API docs.
const (
	defaultTokenURL = "https://auth.idp.hashicorp.com/oauth2/token"
	// Use the Cloud API host for identity introspection.
	defaultAPIBase         = "https://api.cloud.hashicorp.com"
	callerIdentityEndpoint = "/iam/2019-12-10/caller-identity"
)

type cc = ClientCredentials

// NewClientCredentialsValidator creates a new HCP client credential pair validator.
// It validates ClientCredentials by attempting a client_credentials OAuth2
// token exchange against the configured token endpoint. A 200 response indicates
// valid credentials; 400/401 indicates invalid; other responses are treated as
// validation failures.
func NewClientCredentialsValidator(opts ...sv.Option[cc]) *sv.Validator[cc] {
	return sv.New(append([]sv.Option[cc]{
		sv.WithEndpoint[cc](defaultTokenURL),
		sv.WithHTTPMethod[cc](http.MethodPost),
		sv.WithHTTPHeaders(func(_ cc) map[string]string {
			return map[string]string{"Content-Type": "application/x-www-form-urlencoded"}
		}),
		sv.WithBody(func(s cc) string {
			form := url.Values{}
			form.Set("grant_type", "client_credentials")
			form.Set("client_id", s.ClientID)
			form.Set("client_secret", s.ClientSecret)
			return form.Encode()
		}),
		sv.WithValidResponseCodes[cc]([]int{http.StatusOK}),
		sv.WithInvalidResponseCodes[cc]([]int{http.StatusBadRequest, http.StatusUnauthorized}),
	}, opts...)...)
}

type at = AccessToken

// NewAccessTokenValidator creates a new validator for HCP access tokens.
// It validates an AccessToken by sending a GET request to the HCP
// caller-identity endpoint with the token as a Bearer credential.
//
// Documentation: https://developer.hashicorp.com/hcp/api-docs/identity#IamService_GetCallerIdentity
//
// - 200: token is valid (identity returned)
// - 401: token is invalid
// - any other response: treated as ValidationFailed
func NewAccessTokenValidator(opts ...sv.Option[at]) *sv.Validator[at] {
	return sv.New(append([]sv.Option[at]{
		WithAPIBase(defaultAPIBase),
		sv.WithHTTPMethod[at](http.MethodGet),
		sv.WithHTTPHeaders(func(s at) map[string]string {
			return map[string]string{"Authorization": "Bearer " + s.Token}
		}),
		sv.WithValidResponseCodes[at]([]int{http.StatusOK}),
		sv.WithInvalidResponseCodes[at]([]int{http.StatusUnauthorized}),
	}, opts...)...)
}

// WithAPIBase overrides the base API URL (default: https://api.cloud.hashicorp.com).
func WithAPIBase[S at](b string) sv.Option[at] {
	return sv.WithEndpoint[at](b + callerIdentityEndpoint)
}
