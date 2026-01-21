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

// Package squareapikey contains detectors and validators for
// Square API credentials.
package squareapikey

// SquarePersonalAccessToken is a Veles Secret that holds a Square Personal Access Token.
// These tokens allow programmatic access to the Square API.
type SquarePersonalAccessToken struct {
	Key string
}

// SquareOAuthApplicationSecret is a Veles Secret that holds a Square OAuth Application Secret.
// These secrets are used for OAuth authentication flows.
type SquareOAuthApplicationSecret struct {
	ID  string
	Key string
}
