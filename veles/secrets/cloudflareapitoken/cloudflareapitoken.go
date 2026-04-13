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

package cloudflareapitoken

// CloudflareAPIToken is a Veles Secret that holds relevant information for a
// Cloudflare API Token. The detector identifies 40-character alphanumeric tokens
// (including underscores and hyphens) in three formats:
// - Environment variable assignments (e.g., CLOUDFLARE_API_TOKEN=token)
// - JSON key-value pairs (e.g., "cloudflare_api_token": "token")
// - YAML configurations (e.g., cloudflare_api_token: token)
type CloudflareAPIToken struct {
	Token string
}
