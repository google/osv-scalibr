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

package privatekey

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"regexp"

	"github.com/google/osv-scalibr/veles"
)

// PEM keys are typically a few KB
const maxTokenLength = 1280 * 1024

// Regex to match PEM/OpenSSH key blocks
var blockRe = regexp.MustCompile(`(?s)-----BEGIN (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----.*?-----END (?:OPENSSH|RSA|DSA|EC|ED25519|ENCRYPTED)? ?PRIVATE KEY-----`)

var _ veles.Detector = NewDetector()

// detector is a Veles Detector.
type detector struct{}

// NewDetector returns a Detector that extracts and validates private key blocks.
func NewDetector() veles.Detector {
	return &detector{}
}

func (d *detector) MaxSecretLen() uint32 {
	return maxTokenLength
}

func (d *detector) Detect(content []byte) ([]veles.Secret, []int) {
	if len(content) > maxTokenLength {
		return nil, nil
	}

	var secrets []veles.Secret
	var offsets []int

	// 1. PEM detection
	pemMatches := blockRe.FindAllIndex(content, -1)
	for _, m := range pemMatches {
		block := string(content[m[0]:m[1]])
		if validatePEMBlock(block) {
			secrets = append(secrets, PrivateKey{Block: block})
			offsets = append(offsets, m[0])
		}
	}

	// 2. DER detection
	if detectDER(content) {
		secrets = append(secrets, PrivateKey{Der: content})
		offsets = append(offsets, 0)
	}

	return secrets, offsets
}

// validatePEMBlock runs lightweight structural validation on a private key block.
// Returns true if successful, or false otherwise.
func validatePEMBlock(block string) bool {
	p, _ := pem.Decode([]byte(block))
	if p == nil {
		return false
	}

	switch p.Type {
	case "RSA PRIVATE KEY":
		_, err := x509.ParsePKCS1PrivateKey(p.Bytes)
		return err == nil

	case "EC PRIVATE KEY":
		_, err := x509.ParseECPrivateKey(p.Bytes)
		return err == nil

	case "PRIVATE KEY", "ENCRYPTED PRIVATE KEY":
		_, err := x509.ParsePKCS8PrivateKey(p.Bytes)
		return err == nil

	case "DSA PRIVATE KEY", "ED25519 PRIVATE KEY", "OPENSSH PRIVATE KEY":
		// minimal validation, just accept
		return true

	default:
		return false
	}
}

// detectDER tries PKCS#8, PKCS#1, and EC DER encodings.
// Returns true if successful, or false otherwise.
func detectDER(data []byte) bool {
	// PKCS#8 wrapper
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		switch key.(type) {
		case *rsa.PrivateKey:
			return true
		case *ecdsa.PrivateKey:
			return true
		case ed25519.PrivateKey:
			return true
		default:
			return true
		}
	}

	// PKCS#1 RSA
	if _, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return true
	}

	// Raw EC
	if _, err := x509.ParseECPrivateKey(data); err == nil {
		return true
	}

	return false
}
