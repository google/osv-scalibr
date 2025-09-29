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

// Package gcpoauth2client contains Veles Secret types and Detectors for GCP OAuth2 client credentials.
package gcpoauth2client

// Credentials represents a GCP OAuth2 client credential.
//
// See:
// - https://developers.google.com/identity/protocols/oauth2
// - https://developers.google.com/identity/protocols/oauth2/web-server#creatingclient
type Credentials struct {
	// ID is the client ID in format:
	// `12345678901-abcdefghijklmnopqrstuvwxyz.apps.googleusercontent.com`
	ID string
	// Secret is the client secret, typically 24+ character alphanumeric string prefixed with `GOCSPX-`
	Secret string
}
