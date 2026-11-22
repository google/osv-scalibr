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

// Package paypal contains a Veles Secret type, a Detector, and a Validator for
// PayPal REST API credentials.
//
// PayPal REST API apps authenticate to the OAuth 2.0 token endpoint with a
// Client ID and a Client Secret. The Client ID identifies an app; the Client
// Secret authenticates the Client ID. Validation requires both values, so they
// are detected together as a single pair rather than as independent secrets.
//
// References:
//   - https://developer.paypal.com/api/rest/
//   - https://developer.paypal.com/api/rest/authentication/
package paypal

// Credentials is a Veles Secret that holds a PayPal REST API Client ID and
// Client Secret pair.
//
// Both values are issued per app from the PayPal Developer Dashboard
// (Apps & Credentials) and are scoped to either the Sandbox or Live
// environment. Client IDs are URL-safe strings that commonly begin with "A";
// Client Secrets are URL-safe strings that commonly begin with "E". Both are
// typically ~80 characters long.
type Credentials struct {
	// ID is the PayPal REST API Client ID.
	ID string
	// Secret is the PayPal REST API Client Secret.
	Secret string
}
