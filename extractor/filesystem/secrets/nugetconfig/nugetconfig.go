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

// Package nugetconfig contains an extractor for NuGet.config files.
package nugetconfig

import (
	"context"
	"encoding/xml"
	"path"
	"strings"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	velesnugetapikey "github.com/google/osv-scalibr/veles/secrets/nugetapikey"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "secrets/nugetconfig"
)

// ProxyCredential represents HTTP proxy credentials from NuGet.config.
type ProxyCredential struct {
	ProxyURL string
	Username string
	Password string
}

// PackageSourceCredential represents credentials for a private NuGet feed.
type PackageSourceCredential struct {
	SourceName        string
	Username          string
	ClearTextPassword string
	EncryptedPassword string
}

// Extractor extracts NuGet configuration secrets.
type Extractor struct{}

// New returns a new instance of the extractor.
func New(_ *cpb.PluginConfig) (filesystem.Extractor, error) {
	return &Extractor{}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a NuGet.config file.
func (e Extractor) FileRequired(api filesystem.FileAPI) bool {
	fileName := strings.ToLower(path.Base(api.Path()))
	return fileName == "nuget.config" || fileName == ".nuget.config"
}

// nugetConfig represents the structure of a NuGet.config XML file.
type nugetConfig struct {
	XMLName            xml.Name                  `xml:"configuration"`
	Config             configSection             `xml:"config"`
	APIKeys            apiKeysSection            `xml:"apikeys"`
	PackageSourceCreds packageSourceCredsSection `xml:"packageSourceCredentials"`
}

type configSection struct {
	Add []keyValuePair `xml:"add"`
}

type apiKeysSection struct {
	Add []keyValuePair `xml:"add"`
}

type packageSourceCredsSection struct {
	Sources []packageSource `xml:",any"`
}

type packageSource struct {
	XMLName xml.Name
	Add     []keyValuePair `xml:"add"`
}

type keyValuePair struct {
	Key   string `xml:"key,attr"`
	Value string `xml:"value,attr"`
}

// Extract extracts NuGet configuration secrets from NuGet.config files.
func (e Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	decoder := xml.NewDecoder(input.Reader)

	var config nugetConfig
	//nolint:musttag // XML tags are defined on the struct fields
	if err := decoder.Decode(&config); err != nil {
		//nolint:nilerr
		return inventory.Inventory{}, nil
	}

	var secrets []*inventory.Secret

	// Extract proxy credentials from config section
	proxyURL := ""
	proxyUser := ""
	proxyPassword := ""

	for _, item := range config.Config.Add {
		switch item.Key {
		case "http_proxy":
			proxyURL = item.Value
		case "http_proxy.user":
			proxyUser = item.Value
		case "http_proxy.password":
			proxyPassword = item.Value
		}
	}

	if proxyURL != "" && proxyUser != "" && proxyPassword != "" {
		secrets = append(secrets, &inventory.Secret{
			Secret: ProxyCredential{
				ProxyURL: proxyURL,
				Username: proxyUser,
				Password: proxyPassword,
			},
			Location: input.Path,
		})
	}

	// Extract API keys from apikeys section
	for _, item := range config.APIKeys.Add {
		if item.Key != "" && item.Value != "" {
			// The value is the API key
			secrets = append(secrets, &inventory.Secret{
				Secret: velesnugetapikey.NuGetAPIKey{
					Key: item.Value,
				},
				Location: input.Path,
			})
		}
	}

	// Extract package source credentials
	for _, source := range config.PackageSourceCreds.Sources {
		sourceName := source.XMLName.Local
		creds := make(map[string]string)

		for _, item := range source.Add {
			if item.Key != "" && item.Value != "" {
				creds[strings.ToLower(item.Key)] = item.Value
			}
		}

		username := creds["username"]
		clearTextPassword := creds["cleartextpassword"]
		encryptedPassword := creds["password"]

		if username != "" && (clearTextPassword != "" || encryptedPassword != "") {
			secrets = append(secrets, &inventory.Secret{
				Secret: PackageSourceCredential{
					SourceName:        sourceName,
					Username:          username,
					ClearTextPassword: clearTextPassword,
					EncryptedPassword: encryptedPassword,
				},
				Location: input.Path,
			})
		}
	}

	if len(secrets) == 0 {
		return inventory.Inventory{}, nil
	}

	return inventory.Inventory{Secrets: secrets}, nil
}
