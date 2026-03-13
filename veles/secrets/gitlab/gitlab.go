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

// Package gitlab implements the logic to detect GitLab tokens
package gitlab

// PipelineTriggerToken is a Veles Secret that holds relevant information for a
// GitLab Pipeline Trigger Token (prefix `glptt-`).
// Pipeline trigger tokens are used to trigger CI/CD pipelines via API.
type PipelineTriggerToken struct {
	Token     string
	ProjectID string
	Hostname  string // GitLab instance hostname (e.g., "gitlab.com", "gitlab.example.com")
}
