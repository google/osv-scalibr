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

// Package azuretoken contains a Veles Secret type and a Detector for [Azure Tokens](https://learn.microsoft.com/en-us/entra/identity-platform/security-tokens#token-endpoints-and-issuers).
package azuretoken

// AzureAccessToken is a Veles Secret that holds relevant information for a [Azure Access Token](https://learn.microsoft.com/en-us/entra/identity-platform/access-tokens).
type AzureAccessToken struct {
	Token string
}

// AzureIdentityToken is a Veles Secret that holds relevant information for a [Azure ID Token](https://learn.microsoft.com/en-us/entra/identity-platform/id-tokens).
type AzureIdentityToken struct {
	Token string
}
