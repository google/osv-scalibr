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

// Package herokuplatformkey contains a Veles Secret type and a Detector for Heroku Platform API Keys (https://devcenter.heroku.com/articles/platform-api-quickstart).
package herokuplatformkey

import "time"

// HerokuSecret is a Veles Secret that holds relevant information for a Heroku Platform API Key (https://devcenter.heroku.com/articles/oauth#prefixed-oauth-tokens).
type HerokuSecret struct {
	Key string
	// Optional enrichment fields populated by enrichers.
	Metadata *Metadata
}

// Metadata is a Veles Secret Metadata that holds ExpireTime attribute populated by enrichers.
type Metadata struct {
	// ExpireTime is nil if the token doesn't expire
	ExpireTime *time.Duration
}
