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

// Package anthropicapikey contains Veles Secret types and Detectors for Anthropic API keys.
package anthropicapikey

import (
	"strings"
)

// WorkspaceAPIKey is a Veles Secret that holds relevant information for an Anthropic Workspace API key.
// These keys contain "admin01" and are used for workspace management.
type WorkspaceAPIKey struct {
	Key string
}

// ModelAPIKey is a Veles Secret that holds relevant information for an Anthropic Model API key.
// These are regular API keys used for model access.
type ModelAPIKey struct {
	Key string
}

// IsWorkspaceKey checks if the given key string is a workspace key (contains "admin01").
func IsWorkspaceKey(key string) bool {
	return strings.Contains(key, "admin01")
}
