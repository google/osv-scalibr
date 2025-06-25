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

package gcpsak

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

const (
	// hashAlgo is the cryptographic hash function used to hash the payload before
	// signing it.
	// We chose SHA256, because that is what's used in the JWT / OAuth2 flow that
	// GCP SAK are ultimately for.
	// See https://cs.opensource.google/go/x/oauth2/+/refs/tags/v0.20.0:jws/jws.go;l=156 for details.
	hashAlgo = crypto.SHA256

	// payload is used for every signature.
	// We chose a known static payload, so we don't accidentally generate
	// something that could be used for a real authentication flow on an attack on
	// it.
	payload = "Don't leak keys, pretty please!"
)

var (
	// payloadHash contains the (constant) hash of the payload.
	// Since we're using a static payload, we can compute its hash ahead of time.
	payloadHash []byte
)

func init() { //nolint:gochecknoinits
	h := hashAlgo.New()
	if _, err := h.Write([]byte(payload)); err != nil {
		// Guaranteed to never return an error.
		panic(err)
	}
	payloadHash = h.Sum(nil)
}

// Sign uses the privateKey (PEM format) to sign the static payload.
// This allows us to validate a GCP SAK downstream without having to hold on to
// (and thus potentially leak) its private key.
//
// It uses the same flow that the JWT / OAuth2 flow uses for GCP SAK, so we
// don't accidentally expose the key to cross-algorithm attacks. It uses SHA256
// and SignPKCS1v15.
// For details, see https://cs.opensource.google/go/x/oauth2/+/refs/tags/v0.20.0:jws/jws.go;l=156.
//
// Returns nil if signing was not possible; i.e. because the key was not
// well-formed.
func Sign(privateKey string) []byte {
	block, _ := pem.Decode([]byte(privateKey))
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil
	}
	priv, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil
	}
	sig, err := rsa.SignPKCS1v15(nil, priv, hashAlgo, payloadHash)
	if err != nil {
		return nil
	}
	return sig
}

// Valid checks whether sig was signed using the private key contained in the
// certificate cert (PEM format).
//
// Returns true if the signature was successfully validated; false otherwise.
// Returns error if parsing the certificate or extracting the public key failed.
func Valid(sig []byte, cert string) (bool, error) {
	block, _ := pem.Decode([]byte(cert))
	if block == nil || block.Type != "CERTIFICATE" {
		return false, errors.New("no valid PEM block of type CERTIFICATE")
	}
	crt, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, fmt.Errorf("unable to parse certificate: %w", err)
	}
	pub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok {
		return false, fmt.Errorf("public key was %T not RSA public key", crt.PublicKey)
	}
	if err := rsa.VerifyPKCS1v15(pub, hashAlgo, payloadHash, sig); err != nil {
		return false, nil //nolint:nilerr
	}
	return true, nil
}
