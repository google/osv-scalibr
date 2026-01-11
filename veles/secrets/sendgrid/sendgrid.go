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

package sendgrid

// APIKey is a Veles Secret that holds relevant information for a
// SendGrid API key (prefix `SG.`).
// APIKey represents an API key used to authenticate requests to SendGrid.
// It implements veles.Secret.
type APIKey struct {
	Key string
}

// SecretType returns a human-readable description of the secret type.
func (k APIKey) SecretType() string {
	return "SendGrid API Key"
}

// Provider returns the provider/service name.
func (k APIKey) Provider() string {
	return "Twilio SendGrid"
}

// String returns a masked representation of the key for logging purposes.
func (k APIKey) String() string {
	if len(k.Key) > 10 {
		return k.Key[:10] + "..." + k.Key[len(k.Key)-4:]
	}
	return "SG.***"
}
