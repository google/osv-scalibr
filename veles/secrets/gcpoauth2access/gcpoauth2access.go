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

// Package gcpoauth2access contains a Veles Secret type and a Detector for GCP OAuth2 access tokens
// https://cloud.google.com/docs/authentication/token-types#access
package gcpoauth2access

// Token represents a GCP OAuth2 access token.
// https://cloud.google.com/docs/authentication/token-types#access
type Token struct {
	Token string
}
