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

// Package gcpsak contains a Veles Secret type, a Detector, and a Validator for
// GCP service account keys.
package gcpsak

// GCPSAK is a Veles Secret that holds relevant information for a GCP Service
// Account Key.
// It only contains fields necessary for identification and validation.
type GCPSAK struct {
	// PrivateKeyID is the globally unique identifier of the service account key.
	PrivateKeyID string
	// ServiceAccount is the identifier of the service account the key belongs to.
	// It has the structure of an email and is called the "client_email" in the
	// SAK JSON representation.
	ServiceAccount string
	// Signature is a cryptographic signature obtained by using a found GCP SAK's
	// private key to sign a static payload. This is used for out-of-band
	// validation.
	Signature []byte

	// Extra contains optional fields that a Detector can extract but that are not
	// technically required to validate a GCPSAK.
	Extra *ExtraFields
}

// ExtraFields are optional fields for a GCPSAK that a Detector can extract but
// that are not technically required to validate the key.
type ExtraFields struct {
	Type                    string // should always be "service_account"
	ProjectID               string
	ClientID                string
	AuthURI                 string
	TokenURI                string
	AuthProviderX509CertURL string
	ClientX509CertURL       string
	UniverseDomain          string

	// PrivateKey contains the raw private key for the GCP SAK. This field is not
	// populated by default because it creates the risk of accidentally leaking
	// the key.
	PrivateKey string
}
