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

// Package gitlabdeploytoken contains a Veles Secret type, Detector, and Validator
// for GitLab Deploy Tokens (prefix `gldt-`).
package gitlabdeploytoken

// GitlabDeployToken is a Veles Secret that holds relevant information for a
// GitLab Deploy Token (prefix `gldt-`).
// These tokens are used for read-only or read-write access to repositories and registries.
type GitlabDeployToken struct {
	Token    string
	Username string // Format: gitlab+deploy-token-{id} or generic username
	RepoURL  string // Optional: Raw repository URL (parsed during validation using gitlab.ParseRepoURL)
}
