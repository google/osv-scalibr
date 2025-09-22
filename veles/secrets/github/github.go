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

// Package github implements the logic to detect Github tokens
package github

// AppRefreshToken contains a Github App refresh token
type AppRefreshToken struct {
	Token string
}

// AppServerToServerToken contains a Github App server to server token
type AppServerToServerToken struct {
	Token string
}

// PersonalAccessToken contains a Github App personal access token
//
// The underlying value can be either a classic or a fine-grained token
type PersonalAccessToken struct {
	Token string
}
