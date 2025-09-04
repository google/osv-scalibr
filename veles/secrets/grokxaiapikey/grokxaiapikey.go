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

// Package grokxaiapikey contains a detector and validator
// for Grok XAI API keys
package grokxaiapikey

// GrokXAIAPIKey is a Veles Secret that holds a standard xAI API key.
type GrokXAIAPIKey struct {
	Key string
}

// GrokXAIManagementKey is a Veles Secret that holds an xAI management key
// (prefixed with `xai-token-`). Keeping this distinct makes reporting clearer.
type GrokXAIManagementKey struct {
	Key string
}
