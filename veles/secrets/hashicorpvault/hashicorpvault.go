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

// Package hashicorpvault contains Veles Secret types and Detectors for HashiCorp Vault credentials.
package hashicorpvault

// Token is a Veles Secret that holds relevant information for a HashiCorp Vault token.
// Vault tokens are used to authenticate to Vault instances and access secrets.
type Token struct {
	Token string
}

// AppRoleCredentials is a Veles Secret that holds relevant information for HashiCorp Vault AppRole credentials.
// AppRole credentials consist of a role-id and secret-id pair used for authentication.
type AppRoleCredentials struct {
	RoleID   string
	SecretID string
}
