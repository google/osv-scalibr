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

package salesforceoauth2jwt

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv-scalibr/veles"
)

// Validator is a validator for Salesforce OAuth2 JWT Credentials.
type Validator struct {
	HTTPC *http.Client
}

// NewValidator creates a new Validator for Salesforce OAuth2 JWT Credentials.
func NewValidator() *Validator {
	return &Validator{HTTPC: http.DefaultClient}
}

// Validate implements Salesforce OAuth2 JWT validation logic
func (v *Validator) Validate(ctx context.Context, creds Credentials) (veles.ValidationStatus, error) {
	// 1. Parse and validate private key
	key, err := parsePrivateKey(creds.PrivateKey)
	if err != nil {
		return veles.ValidationInvalid, fmt.Errorf("invalid private key: %w", err)
	}
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return veles.ValidationInvalid, errors.New("only RSA private keys are supported for Salesforce JWT")
	}

	// 2. Build JWT components
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256"}`))

	exp := time.Now().Unix() + 300
	jti := strconv.FormatInt(time.Now().UnixNano(), 10)

	claim := fmt.Sprintf(
		`{"iss":"%s","sub":"%s","aud":"https://login.salesforce.com","exp":%d,"jti":"%s"}`,
		creds.ID,
		creds.Username,
		exp,
		jti,
	)

	claimB64 := base64.RawURLEncoding.EncodeToString([]byte(claim))

	signingInput := header + "." + claimB64

	// 3. Sign using RSA SHA256
	h := sha256.Sum256([]byte(signingInput))
	sig, err := rsa.SignPKCS1v15(rand.Reader, rsaKey, crypto.SHA256, h[:])
	if err != nil {
		return veles.ValidationFailed, fmt.Errorf("signing failed: %w", err)
	}

	sigB64 := base64.RawURLEncoding.EncodeToString(sig)
	jwt := signingInput + "." + sigB64

	// 4. Call Salesforce OAuth2 JWT endpoint
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:jwt-bearer")
	form.Set("assertion", jwt)

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		"https://login.salesforce.com/services/oauth2/token",
		strings.NewReader(form.Encode()),
	)
	if err != nil {
		return veles.ValidationFailed, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.HTTPC.Do(req)
	if err != nil {
		return veles.ValidationFailed, err
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
		return veles.ValidationValid, nil

	case http.StatusUnauthorized, http.StatusBadRequest:
		return veles.ValidationInvalid, nil

	default:
		return veles.ValidationFailed, fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}
}

// parsePrivateKey handles PEM or raw DER
func parsePrivateKey(input string) (crypto.PrivateKey, error) {
	block, _ := pem.Decode([]byte(input))
	if block != nil {
		// PEM → try PKCS8 then PKCS1
		if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
			return key, nil
		}
		return nil, errors.New("PEM parsed but not a valid RSA key")
	}

	// Raw DER
	if key, err := x509.ParsePKCS8PrivateKey([]byte(input)); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey([]byte(input)); err == nil {
		return key, nil
	}

	return nil, errors.New("could not parse private key")
}
