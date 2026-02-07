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

// Package supabase contains detectors for Supabase credentials.
package supabase

// PAT is a Veles Secret that holds a Supabase Personal Access Token.
// These tokens are used to authenticate with the Supabase Management API.
type PAT struct {
	Token string
}

// ProjectSecretKey is a Veles Secret that holds a Supabase Project Secret Key.
// When the ProjectRef field is populated, it indicates both credentials were found together
// and validation can be performed against the project-specific endpoint.
type ProjectSecretKey struct {
	Key        string
	ProjectRef string
}

// ServiceRoleJWT is a Veles Secret that holds a Supabase service_role JWT.
// This is a long-lived JWT with unrestricted privileges that bypasses RLS.
type ServiceRoleJWT struct {
	Token string
}
