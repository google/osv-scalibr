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

// AppUserToServerToken contains a user to server token
//
// A Github App User to Server token is a temporary, secure credential that allows a GitHub App
// to perform actions on the platform on behalf of a user
type AppUserToServerToken struct {
	Token string
}

// ClassicPersonalAccessToken contains a Github classic personal access token
type ClassicPersonalAccessToken struct {
	Token string
}

// FineGrainedPersonalAccessToken contains a Github fine-grained personal access token
type FineGrainedPersonalAccessToken struct {
	Token string
}

// OAuthToken contains an oauth token
type OAuthToken struct {
	Token string
}
