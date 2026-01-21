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

// Package circleci contains detectors for CircleCI API credentials.
package circleci

// PersonalAccessToken is a Veles Secret that holds a CircleCI Personal Access Token.
// These tokens use the CCIPAT_ prefix and are used to authenticate with the CircleCI API v2.
type PersonalAccessToken struct {
	Token string
}

// ProjectToken is a Veles Secret that holds a CircleCI Project Token.
// These tokens use the CCIPRJ_ prefix and are used to authenticate with the CircleCI API v1.1.
type ProjectToken struct {
	Token string
}
