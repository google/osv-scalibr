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

// Package bitwardenoauth2access contains a Veles Secret type, Detector, and Validator
// for Bitwarden OAuth2 access tokens. Detects client ID (UUID) and client secret
// from Bitwarden CLI data.json files with key pattern:
// "user_<UUID>_token_apiKeyClientSecret": "<secret>"
package bitwardenoauth2access

// Token is a Veles Secret that holds relevant information for a
// Bitwarden OAuth2 access token, including the client ID (UUID extracted
// from the JSON key) and the client secret (the JSON value).
type Token struct {
	ClientID     string
	ClientSecret string
}
