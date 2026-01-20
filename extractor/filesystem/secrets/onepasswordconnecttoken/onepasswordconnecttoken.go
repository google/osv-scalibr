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

// Package onepasswordconnecttoken contains an extractor for OnePassword Connect Token files.
package onepasswordconnecttoken

import (
	"context"
	"encoding/json"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
)

// OnePasswordConnectToken is a Veles Secret that holds a OnePassword Connect Token
// with all its encrypted credentials and metadata.
type OnePasswordConnectToken struct {
	DeviceUUID        string
	Version           string
	EncryptedData     string
	EncryptionKeyID   string
	IV                string
	UniqueKeyID       string
	VerifierSalt      string
	VerifierLocalHash string
}

const (
	// Name is the unique name of this extractor.
	Name = "secrets/onepasswordconnecttoken"
)

// TokenData represents the structure of a OnePassword Connect Token JSON file.
type TokenData struct {
	Verifier struct {
		Salt      string `json:"salt"`
		LocalHash string `json:"localHash"`
	} `json:"verifier"`
	EncCredentials struct {
		Kid  string `json:"kid"`
		Enc  string `json:"enc"`
		Cty  string `json:"cty"`
		IV   string `json:"iv"`
		Data string `json:"data"`
	} `json:"encCredentials"`
	Version    string `json:"version"`
	DeviceUUID string `json:"deviceUuid"`
	UniqueKey  struct {
		Alg    string   `json:"alg"`
		Ext    bool     `json:"ext"`
		K      string   `json:"k"`
		KeyOps []string `json:"key_ops"`
		Kty    string   `json:"kty"`
		Kid    string   `json:"kid"`
	} `json:"uniqueKey"`
}

// Extractor extracts OnePassword Connect Token secrets.
type Extractor struct{}

// New returns a new instance of the extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a JSON file with "onepassword" or "1password" in its name.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	fileName := strings.ToLower(path.Base(api.Path()))

	// Check if the filename contains "onepassword" or "1password"
	if !strings.Contains(fileName, "onepassword") && !strings.Contains(fileName, "1password") {
		return false
	}

	// Check if it's a JSON file
	return strings.HasSuffix(fileName, ".json")
}

// Extract extracts OnePassword Connect Token information from JSON files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	var data TokenData

	decoder := json.NewDecoder(input.Reader)
	if err := decoder.Decode(&data); err != nil {
		// Not a valid JSON or not a OnePassword Connect Token file, return empty inventory
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	// Check if this looks like a OnePassword Connect Token file by verifying required fields
	if data.DeviceUUID == "" || data.Version == "" || data.EncCredentials.Data == "" {
		// Not a OnePassword Connect Token file, return empty inventory
		return inventory.Inventory{}, nil
	}

	var secrets []*inventory.Secret

	secret := &inventory.Secret{
		Secret: OnePasswordConnectToken{
			DeviceUUID:        data.DeviceUUID,
			Version:           data.Version,
			EncryptedData:     data.EncCredentials.Data,
			EncryptionKeyID:   data.EncCredentials.Kid,
			IV:                data.EncCredentials.IV,
			UniqueKeyID:       data.UniqueKey.Kid,
			VerifierSalt:      data.Verifier.Salt,
			VerifierLocalHash: data.Verifier.LocalHash,
		},
		Location: input.Path,
	}

	secrets = append(secrets, secret)

	return inventory.Inventory{Secrets: secrets}, nil
}
