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

// Package privatekey provides a detector for identifying private key material
// in scanned files and data streams.
package privatekey

// PrivateKey is a Veles Secret representing a PEM/OpenSSH private key block.
type PrivateKey struct {
	// Block is the full matched BEGIN...END block (no redaction here; SCALIBR
	// downstream can mask/clip as needed).
	Block string
	// Der contains the raw DER-encoded private key bytes (e.g., PKCS#1, PKCS#8, or EC).
	// This field is left unredacted; SCALIBR downstream can decide how to mask or
	// clip the data if needed.
	Der []byte
}
