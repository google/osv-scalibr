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

package denopat

// DenoUserPAT is a Veles Secret that holds relevant information for a
// Deno Hub User Personal Access Token (prefix `ddp_`).
// User tokens are used to authenticate user requests.
type DenoUserPAT struct {
	Pat string
}

// DenoOrgPAT is a Veles Secret that holds relevant information for a
// Deno Hub Organization Personal Access Token (prefix `ddo_`).
// Organization tokens are used to authenticate organization requests.
type DenoOrgPAT struct {
	Pat string
}
