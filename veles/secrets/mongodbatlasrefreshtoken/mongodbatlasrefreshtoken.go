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

package mongodbatlasrefreshtoken

// MongoDBAtlasRefreshToken is a Veles Secret that holds relevant information for a
// MongoDB Atlas Access Token and optional Refresh Token. The detector identifies
// Okta-issued JWT tokens (three base64url-encoded segments separated by dots)
// and refresh tokens (base64url-encoded strings) in TOML configuration files
// (e.g., atlascli/config.toml) with key-value assignments like:
//   - access_token = 'eyJ...'
//   - refresh_token = 'ZkHO...'
type MongoDBAtlasRefreshToken struct {
	Token string
}
