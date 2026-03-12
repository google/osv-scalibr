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

// Package paypal contains detectors and validators for PayPal API credentials.
//
// PayPal REST API apps use a Client ID and Client Secret for OAuth 2.0
// authentication. The Client ID identifies an app, while the Client Secret
// authenticates the Client ID. Together they are exchanged for an access token
// to call PayPal APIs.
//
// References:
//   - https://developer.paypal.com/api/rest/
//   - https://developer.paypal.com/api/rest/authentication/
package paypal

// ClientID is a Veles Secret that holds a PayPal REST API Client ID.
//
// PayPal Client IDs are alphanumeric strings that start with "A" and are
// approximately 80 characters long. They are used to identify a PayPal app
// and are required for all REST API calls.
type ClientID struct {
	Key string
}

// ClientSecret is a Veles Secret that holds a PayPal REST API Client Secret.
//
// PayPal Client Secrets are alphanumeric strings (including hyphens and
// underscores) that are approximately 80 characters long. They authenticate
// a Client ID and must be kept secure.
type ClientSecret struct {
	Key string
}
