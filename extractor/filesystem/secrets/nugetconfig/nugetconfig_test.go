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

package nugetconfig_test

import (
	"context"
	"io/fs"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/extractor/filesystem/secrets/nugetconfig"
	"github.com/google/osv-scalibr/extractor/filesystem/simplefileapi"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/testing/fakefs"
	velesnugetapikey "github.com/google/osv-scalibr/veles/secrets/nugetapikey"
)

func TestFileRequired(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{
			name:     "nuget_config_lowercase",
			path:     "/path/to/nuget.config",
			expected: true,
		},
		{
			name:     "nuget_config_uppercase",
			path:     "/path/to/NuGet.Config",
			expected: true,
		},
		{
			name:     "nuget_config_mixed_case",
			path:     "/path/to/NuGet.config",
			expected: true,
		},
		{
			name:     "hidden_nuget_config",
			path:     "/path/to/.nuget.config",
			expected: true,
		},
		{
			name:     "other_xml_file",
			path:     "/path/to/packages.config",
			expected: false,
		},
		{
			name:     "json_file",
			path:     "/path/to/nuget.json",
			expected: false,
		},
		{
			name:     "no_extension",
			path:     "/path/to/nuget",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := nugetconfig.Extractor{}
			got := e.FileRequired(simplefileapi.New(tt.path, nil))
			if got != tt.expected {
				t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.expected)
			}
		})
	}
}

func TestExtract(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		content string
		want    inventory.Inventory
	}{
		{
			name: "complete_config_with_all_secrets",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config>
    <add key="http_proxy" value="http://corp-proxy.internal.local:8080" />
    <add key="http_proxy.user" value="buildsvc" />
    <add key="http_proxy.password" value="P@ssw0rdProxy!" />
  </config>
  <packageSourceCredentials>
    <AzureArtifacts>
      <add key="Username" value="buildagent" />
      <add key="ClearTextPassword" value="azdov_pat_ghp_1234567890abcdef1234567890abcdef" />
    </AzureArtifacts>
    <GitHubPackages>
      <add key="Username" value="contoso-ci" />
      <add key="ClearTextPassword" value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" />
    </GitHubPackages>
    <Artifactory>
      <add key="Username" value="ci-user" />
      <add key="Password" value="AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA..." />
    </Artifactory>
  </packageSourceCredentials>
  <apikeys>
    <add key="https://api.nuget.org/v3/index.json" value="oy2k4q9qmzverylo1234567890abcdef1234567890ab" />
    <add key="https://contoso.jfrog.io/artifactory/api/nuget/nuget-local" value="jfrog9d8f7a6b5c4e3d2c1b0a1234567890abcdef12" />
  </apikeys>
</configuration>`,
			want: inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Secret: nugetconfig.ProxyCredential{
							ProxyURL: "http://corp-proxy.internal.local:8080",
							Username: "buildsvc",
							Password: "P@ssw0rdProxy!",
						},
						Location: "/path/to/nuget.config",
					},
					{
						Secret: velesnugetapikey.NuGetAPIKey{
							Key: "oy2k4q9qmzverylo1234567890abcdef1234567890ab",
						},
						Location: "/path/to/nuget.config",
					},
					{
						Secret: velesnugetapikey.NuGetAPIKey{
							Key: "jfrog9d8f7a6b5c4e3d2c1b0a1234567890abcdef12",
						},
						Location: "/path/to/nuget.config",
					},
					{
						Secret: nugetconfig.PackageSourceCredential{
							SourceName:        "AzureArtifacts",
							Username:          "buildagent",
							ClearTextPassword: "azdov_pat_ghp_1234567890abcdef1234567890abcdef",
						},
						Location: "/path/to/nuget.config",
					},
					{
						Secret: nugetconfig.PackageSourceCredential{
							SourceName:        "GitHubPackages",
							Username:          "contoso-ci",
							ClearTextPassword: "ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890",
						},
						Location: "/path/to/nuget.config",
					},
					{
						Secret: nugetconfig.PackageSourceCredential{
							SourceName:        "Artifactory",
							Username:          "ci-user",
							EncryptedPassword: "AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA...",
						},
						Location: "/path/to/nuget.config",
					},
				},
			},
		},
		{
			name: "only_api_keys",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <apikeys>
    <add key="https://api.nuget.org/v3/index.json" value="oy2k4q9qmzverylo1234567890abcdef1234567890ab" />
  </apikeys>
</configuration>`,
			want: inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Secret: velesnugetapikey.NuGetAPIKey{
							Key: "oy2k4q9qmzverylo1234567890abcdef1234567890ab",
						},
						Location: "/path/to/nuget.config",
					},
				},
			},
		},
		{
			name: "only_proxy_credentials",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config>
    <add key="http_proxy" value="http://proxy.example.com:8080" />
    <add key="http_proxy.user" value="proxyuser" />
    <add key="http_proxy.password" value="proxypass123" />
  </config>
</configuration>`,
			want: inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Secret: nugetconfig.ProxyCredential{
							ProxyURL: "http://proxy.example.com:8080",
							Username: "proxyuser",
							Password: "proxypass123",
						},
						Location: "/path/to/nuget.config",
					},
				},
			},
		},
		{
			name: "only_package_source_credentials",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSourceCredentials>
    <MyFeed>
      <add key="Username" value="myuser" />
      <add key="ClearTextPassword" value="mypassword123" />
    </MyFeed>
  </packageSourceCredentials>
</configuration>`,
			want: inventory.Inventory{
				Secrets: []*inventory.Secret{
					{
						Secret: nugetconfig.PackageSourceCredential{
							SourceName:        "MyFeed",
							Username:          "myuser",
							ClearTextPassword: "mypassword123",
						},
						Location: "/path/to/nuget.config",
					},
				},
			},
		},
		{
			name: "incomplete_proxy_credentials",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config>
    <add key="http_proxy" value="http://proxy.example.com:8080" />
    <add key="http_proxy.user" value="proxyuser" />
  </config>
</configuration>`,
			want: inventory.Inventory{},
		},
		{
			name: "incomplete_package_source_credentials",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <packageSourceCredentials>
    <MyFeed>
      <add key="Username" value="myuser" />
    </MyFeed>
  </packageSourceCredentials>
</configuration>`,
			want: inventory.Inventory{},
		},
		{
			name: "empty_config",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
</configuration>`,
			want: inventory.Inventory{},
		},
		{
			name:    "invalid_xml",
			path:    "/path/to/nuget.config",
			content: `not valid xml`,
			want:    inventory.Inventory{},
		},
		{
			name: "config_with_other_settings",
			path: "/path/to/nuget.config",
			content: `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <config>
    <add key="globalPackagesFolder" value="C:\Users\dev\.nuget\packages" />
    <add key="dependencyVersion" value="HighestMinor" />
  </config>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
  </packageSources>
</configuration>`,
			want: inventory.Inventory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := nugetconfig.Extractor{}
			input := &filesystem.ScanInput{
				Path:   tt.path,
				Reader: strings.NewReader(tt.content),
				Info:   fakefs.FakeFileInfo{},
			}

			got, err := e.Extract(context.Background(), input)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, got, cmpopts.SortSlices(func(a, b *inventory.Secret) bool {
				return a.Location < b.Location
			})); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_RealWorldExample(t *testing.T) {
	content := `<?xml version="1.0" encoding="utf-8"?>
<configuration>
  <!-- General behaviour -->
  <config>
    <add key="globalPackagesFolder" value="C:\Users\dev\.nuget\packages" />
    <add key="dependencyVersion" value="HighestMinor" />
    <add key="signatureValidationMode" value="accept" />
    
    <!-- Corporate proxy credentials -->
    <add key="http_proxy" value="http://corp-proxy.internal.local:8080" />
    <add key="http_proxy.user" value="buildsvc" />
    <add key="http_proxy.password" value="P@ssw0rdProxy!" />
  </config>
  
  <!-- Package repositories -->
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="AzureArtifacts" value="https://pkgs.dev.azure.com/contoso/_packaging/InternalFeed/nuget/v3/index.json" />
    <add key="GitHubPackages" value="https://nuget.pkg.github.com/contoso/index.json" />
    <add key="Artifactory" value="https://contoso.jfrog.io/artifactory/api/nuget/nuget-virtual" />
  </packageSources>
  
  <!-- Credentials for private feeds -->
  <packageSourceCredentials>
    <AzureArtifacts>
      <add key="Username" value="buildagent" />
      <add key="ClearTextPassword" value="azdov_pat_ghp_1234567890abcdef1234567890abcdef" />
    </AzureArtifacts>
    
    <GitHubPackages>
      <add key="Username" value="contoso-ci" />
      <add key="ClearTextPassword" value="ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234567890" />
    </GitHubPackages>
    
    <Artifactory>
      <add key="Username" value="ci-user" />
      <add key="Password" value="AQAAANCMnd8BFdERjHoAwE/Cl+sBAAAA..." />
    </Artifactory>
  </packageSourceCredentials>
  
  <!-- Publish API keys -->
  <apikeys>
    <add key="https://api.nuget.org/v3/index.json" value="oy2k4q9qmzverylo1234567890abcdef1234567890ab" />
    <add key="https://contoso.jfrog.io/artifactory/api/nuget/nuget-local" value="jfrog9d8f7a6b5c4e3d2c1b0a1234567890abcdef12" />
  </apikeys>
  
  <!-- Trusted signers -->
  <trustedSigners>
    <author name="Contoso">
      <certificate fingerprint="‎3F9001EA9F9DCE9F1A21A1E01B6F5C1D4B9E8C2A" hashAlgorithm="SHA256" allowUntrustedRoot="false" />
    </author>
  </trustedSigners>
</configuration>`

	e := nugetconfig.Extractor{}
	input := &filesystem.ScanInput{
		Path:   "/path/to/nuget.config",
		Reader: strings.NewReader(content),
		Info:   fakefs.FakeFileInfo{},
	}

	got, err := e.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	// Verify we extracted all expected secrets
	if len(got.Secrets) != 6 {
		t.Errorf("Extract() returned %d secrets, want 6", len(got.Secrets))
	}

	// Verify we have the expected types
	var (
		proxyCount       int
		apiKeyCount      int
		packageCredCount int
	)

	for _, secret := range got.Secrets {
		switch secret.Secret.(type) {
		case nugetconfig.ProxyCredential:
			proxyCount++
		case velesnugetapikey.NuGetAPIKey:
			apiKeyCount++
		case nugetconfig.PackageSourceCredential:
			packageCredCount++
		}
	}

	if proxyCount != 1 {
		t.Errorf("Extract() found %d proxy credentials, want 1", proxyCount)
	}
	if apiKeyCount != 2 {
		t.Errorf("Extract() found %d API keys, want 2", apiKeyCount)
	}
	if packageCredCount != 3 {
		t.Errorf("Extract() found %d package source credentials, want 3", packageCredCount)
	}
}

var _ fs.FileInfo = fakefs.FakeFileInfo{}
