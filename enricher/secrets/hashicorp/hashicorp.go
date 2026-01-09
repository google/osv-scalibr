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

// Package hashicorp provides initialization logic for HashiCorp-related enrichers.
package hashicorp

import (
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/secrets/convert"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/veles/secrets/hashicorpvault"
)

func vaultURL(cfg *cpb.PluginConfig) string {
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.HashiCorpVaultValidatorConfig {
		return c.GetHashicorpVaultValidator()
	})
	return specific.GetVaultUrl()
}

// NewTokenValidatorEnricher returns an enricher for Hashicorp token validation.
//
// The enricher is initialized with the vault URL from the config. If the URL is not set,
// an empty string is used, which will cause the validation to fail.
func NewTokenValidatorEnricher(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	return convert.FromVelesValidator(hashicorpvault.NewTokenValidator(vaultURL(cfg)), "secrets/hashicorpvaulttokenvalidate", 0)(), nil
}

// NewAppRoleValidatorEnricher returns an enricher for Hashicorp app role validation.
//
// The enricher is initialized with the vault URL from the config. If the URL is not set,
// an empty string is used, which will cause the validation to fail.
func NewAppRoleValidatorEnricher(cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	return convert.FromVelesValidator(hashicorpvault.NewAppRoleValidator(vaultURL(cfg)), "secrets/hashicorpvaultapprolevalidate", 0)(), nil
}
