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

// Package deepseekapikey contains Veles Secret types and Detectors for DeepSeek API keys.
package deepseekapikey

// APIKey is a Veles Secret that holds relevant information for a DeepSeek API
// key. DeepSeek API keys start with "sk-" followed by 32 alphanumeric
// characters and are used to authenticate with the DeepSeek AI API service.
type APIKey struct {
	Key string
}
