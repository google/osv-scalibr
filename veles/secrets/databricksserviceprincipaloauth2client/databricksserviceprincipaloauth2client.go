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

// Package databricksserviceprincipaloauth2client contains Veles Secret types and Detectors for Databricks Service Principal OAuth2 Client Credentials.
package databricksserviceprincipaloauth2client

// Credentials represents a Databricks Service Principal OAuth2 Client Credentials.
type Credentials struct {
	// URL is the Databricks Service Principal Workspace URL
	URL string
	// Secret is the Databricks Service Principal OAuth2 Client Secret
	Secret string
	// ID is the Databricks Service Principal OAuth2 Client ID
	ID string
}
