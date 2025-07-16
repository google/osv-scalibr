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

// Package gcpexpressmode contains a Veles Detector for GCP Express Mode API keys.
//
// GCP Express mode exists to facilitate Vertex AI demos, see https://cloud.google.com/resources/cloud-express-faqs?hl=en and https://cloud.google.com/vertex-ai/generative-ai/docs/start/express-mode/overview.
package gcpexpressmode

// APIKey is a GCP Express Mode API Key that can be used to access Vertex AI demos.
type APIKey struct {
	Key string
}
