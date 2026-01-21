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

// Package packagist contains detectors for Packagist API credentials.
package packagist

// APIKey is a Veles Secret that holds a Packagist API Key.
// These keys are used to authenticate with the Packagist API.
type APIKey struct {
	Key string
}

// APISecret is a Veles Secret that holds a Packagist API Secret.
// When the Key field is populated, it indicates both credentials were found together
// and HMAC-SHA256 validation can be performed.
type APISecret struct {
	Secret string
	Key    string // Optional: populated when both key and secret are found together
}
