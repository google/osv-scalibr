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

// Package mistralapikey contains a Veles Secret type, Detector and Validator
// for Mistral API keys.
package mistralapikey

// MistralAPIKey is a Veles Secret that holds a Mistral API key.
// Mistral API keys are 32-character alphanumeric strings without a specific
// prefix, so they require context-based detection (e.g., nearby keywords
// like "mistral", "mistralai", "api.mistral.ai").
type MistralAPIKey struct {
	Key string
}
