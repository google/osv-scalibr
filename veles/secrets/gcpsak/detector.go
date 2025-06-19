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
	"encoding/base64"
	"regexp"

	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/common/flatjson"
)

var (
	// Matches on "auth_provider_x509_cert_url" somewhere between curly braces.
	// This matches very broadly and gives us some vague "JSON context" that we
	// can further refine on.
	reJSON = regexp.MustCompile(`\{[^{]+auth_provider_x509_cert_url[^}]+\}`)

	// Matches on a base64-encoded GCP service account key (in pretty JSON
	// format). This relies on consistent field order and whitespace.
	// That should be a reasonable heuristic. Note that this means we will miss
	// (false negatives) base64-encoded GCP SAK that have been modified before
	// encoding.
	reBase64 = regexp.MustCompile(`ewogICJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIs[a-zA-Z0-9/+]{52,}`)

	// requiredKeys are the keys that must be present in a candidate's JSON
	// representation for the Detector to produce a result.
	requiredKeys = []string{"private_key_id", "private_key", "client_email"}

	// optionalKeys are not required to be present but are reported as part of a
	// GCPSAK if they are.
	optionalKeys = []string{
		"type",
		"project_id",
		"client_id",
		"auth_uri",
		"token_uri",
		"auth_provider_x509_cert_url",
		"client_x509_cert_url",
		"universe_domain",
	}
)

var _ veles.Detector = NewDetector()

// Detector is a Veles Detector that finds GCP service account keys.
//
// It can find GCP SAK in plain JSON format (even if it's modified or escaped)
// and base64 encoded but only if it wasn't modified before encoding.
type Detector struct {
	ex             *flatjson.Extractor
	withExtra      bool
	withPrivateKey bool
}

// NewDetector returns a new Veles Detector that finds GCP service account keys.
func NewDetector() *Detector {
	return &Detector{
		ex:        flatjson.NewExtractor(requiredKeys, nil),
		withExtra: false,
	}
}

// NewDetectorWithExtraFields returns a new Veles Detector that finds GCP
// service account keys and returns them with all their fields not just those
// needed for validation.
//
// If includePrivateKey is set, the result will also contain the raw private
// key. This should generally be avoided because it creates the risk of
// accidentally leaking the key.
func NewDetectorWithExtraFields(includePrivateKey bool) *Detector {
	return &Detector{
		ex:             flatjson.NewExtractor(requiredKeys, optionalKeys),
		withExtra:      true,
		withPrivateKey: includePrivateKey,
	}
}

// MaxSecretLen returns the maximum length a secret from this Detector can have.
//
// Since GCP SAK contain an entire PEM-encoded 2048 bit RSA private key, they
// can be pretty long. For now, we use 4 kiB just to be on the safe side.
func (d *Detector) MaxSecretLen() uint32 {
	return 4096
}

// Detect finds candidate GCP SAK in the data and returns them alongside their
// starting positions.
func (d *Detector) Detect(data []byte) ([]veles.Secret, []int) {
	sJSON, pJSON := d.detectJSON(data)
	sB64, pB64 := d.detectB64(data)
	return append(sJSON, sB64...), append(pJSON, pB64...)
}

func (d *Detector) detectJSON(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int
	for _, m := range reJSON.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		sak := d.extractJSON(data[l:r])
		if sak == nil {
			continue
		}
		secrets = append(secrets, *sak)
		positions = append(positions, l)
	}
	return secrets, positions
}

func (d *Detector) detectB64(data []byte) ([]veles.Secret, []int) {
	var secrets []veles.Secret
	var positions []int
	for _, m := range reBase64.FindAllIndex(data, -1) {
		l, r := m[0], m[1]
		buf := data[l:r]
		dec := make([]byte, base64.RawStdEncoding.DecodedLen(len(buf)))
		n, err := base64.RawStdEncoding.Decode(dec, buf)
		if err != nil {
			continue
		}
		sak := d.extractJSON(dec[:n])
		if sak == nil {
			continue
		}
		secrets = append(secrets, *sak)
		positions = append(positions, l)
	}
	return secrets, positions
}

func (d *Detector) extractJSON(data []byte) *GCPSAK {
	kv := d.ex.Extract(data)
	if kv == nil {
		return nil
	}
	sig := Sign(kv["private_key"])
	if sig == nil {
		return nil
	}
	sak := &GCPSAK{
		PrivateKeyID:   kv["private_key_id"],
		ServiceAccount: kv["client_email"],
		Signature:      sig,
	}
	if d.withExtra {
		sak.Extra = &ExtraFields{
			Type:                    kv["type"],
			ProjectID:               kv["project_id"],
			ClientID:                kv["client_id"],
			AuthURI:                 kv["auth_uri"],
			TokenURI:                kv["token_uri"],
			AuthProviderX509CertURL: kv["auth_provider_x509_cert_url"],
			ClientX509CertURL:       kv["client_x509_cert_url"],
			UniverseDomain:          kv["universe_domain"],
		}
		if d.withPrivateKey {
			sak.Extra.PrivateKey = kv["private_key"]
		}
	}
	return sak
}
