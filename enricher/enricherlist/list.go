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

// Package enricherlist provides methods to initialize enrichers from attributes like names or capabilities.
package enricherlist

import (
	"fmt"
	"maps"
	"slices"

	"github.com/google/osv-scalibr/enricher"
	"github.com/google/osv-scalibr/enricher/baseimage"
	govcsource "github.com/google/osv-scalibr/enricher/govulncheck/source"
	"github.com/google/osv-scalibr/enricher/hcpidentity"
	"github.com/google/osv-scalibr/enricher/huggingfacemeta"
	"github.com/google/osv-scalibr/enricher/license"
	"github.com/google/osv-scalibr/enricher/packagedeprecation"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/enricher/reachability/rust"
	"github.com/google/osv-scalibr/enricher/secrets/convert"
	"github.com/google/osv-scalibr/enricher/secrets/hashicorp"
	"github.com/google/osv-scalibr/enricher/transitivedependency/pomxml"
	"github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/enricher/vex/filter"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	"github.com/google/osv-scalibr/veles/secrets/awsaccesskey"
	"github.com/google/osv-scalibr/veles/secrets/cratesioapitoken"
	"github.com/google/osv-scalibr/veles/secrets/cursorapikey"
	"github.com/google/osv-scalibr/veles/secrets/digitaloceanapikey"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
	"github.com/google/osv-scalibr/veles/secrets/elasticcloudapikey"
	"github.com/google/osv-scalibr/veles/secrets/gcpoauth2access"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	"github.com/google/osv-scalibr/veles/secrets/gcshmackey"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/bitbucket"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecatalyst"
	"github.com/google/osv-scalibr/veles/secrets/gitbasicauth/codecommit"
	"github.com/google/osv-scalibr/veles/secrets/github"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
	"github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
	"github.com/google/osv-scalibr/veles/secrets/hcp"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
	"github.com/google/osv-scalibr/veles/secrets/openai"
	"github.com/google/osv-scalibr/veles/secrets/openrouter"
	"github.com/google/osv-scalibr/veles/secrets/packagist"
	"github.com/google/osv-scalibr/veles/secrets/paystacksecretkey"
	"github.com/google/osv-scalibr/veles/secrets/perplexityapikey"
	"github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	"github.com/google/osv-scalibr/veles/secrets/pypiapitoken"
	"github.com/google/osv-scalibr/veles/secrets/slacktoken"
	"github.com/google/osv-scalibr/veles/secrets/stripeapikeys"
	"github.com/google/osv-scalibr/veles/secrets/telegrambotapitoken"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

// InitFn is the enricher initializer function.
type InitFn func(cfg *cpb.PluginConfig) (enricher.Enricher, error)

// InitMap is a map of names to enricher initializer functions.
type InitMap map[string][]InitFn

var (

	// LayerDetails enrichers.
	LayerDetails = InitMap{
		baseimage.Name: {noCFG(baseimage.NewDefault)},
	}

	// License enrichers.
	License = InitMap{
		license.Name: {noCFG(license.New)},
	}

	// VulnMatching enrichers.
	VulnMatching = InitMap{

		osvdev.Name: {noCFG(osvdev.NewDefault)},
	}

	// VEX related enrichers.
	VEX = InitMap{
		filter.Name: {noCFG(filter.New)},
	}

	// SecretsValidate lists secret validators.
	SecretsValidate = initMapFromVelesPlugins([]velesPlugin{
		fromVeles(anthropicapikey.NewWorkspaceValidator(), "secrets/anthropicapikeyworkspacevalidate", 0),
		fromVeles(anthropicapikey.NewModelValidator(), "secrets/anthropicapikeymodelvalidate", 0),
		fromVeles(digitaloceanapikey.NewValidator(), "secrets/digitaloceanapikeyvalidate", 0),
		fromVeles(elasticcloudapikey.NewValidator(), "secrets/elasticcloudapikeyvalidate", 0),
		fromVeles(pypiapitoken.NewValidator(), "secrets/pypiapitokenvalidate", 0),
		fromVeles(cratesioapitoken.NewValidator(), "secrets/cratesioapitokenvalidate", 0),
		fromVeles(slacktoken.NewAppLevelTokenValidator(), "secrets/slackappleveltokenvalidate", 0),
		fromVeles(slacktoken.NewAppConfigRefreshTokenValidator(), "secrets/slackconfigrefreshtokenvalidate", 0),
		fromVeles(slacktoken.NewAppConfigAccessTokenValidator(), "secrets/slackconfigaccesstokenvalidate", 0),
		fromVeles(dockerhubpat.NewValidator(), "secrets/dockerhubpatvalidate", 0),
		fromVeles(gcpsak.NewValidator(), "secrets/gcpsakvalidate", 0),
		fromVeles(gitlabpat.NewValidator(), "secrets/gitlabpatvalidate", 0),
		fromVeles(grokxaiapikey.NewAPIValidator(), "secrets/grokxaiapikeyvalidate", 0),
		fromVeles(grokxaiapikey.NewManagementAPIValidator(), "secrets/grokxaimanagementkeyvalidate", 0),
		fromVelesWithCfg(hashicorp.NewTokenValidatorEnricher, "secrets/hashicorpvaulttokenvalidate"),
		fromVelesWithCfg(hashicorp.NewAppRoleValidatorEnricher, "secrets/hashicorpvaultapprolevalidate"),
		fromVeles(hcp.NewClientCredentialsValidator(), "secrets/hcpclientcredentialsvalidate", 0),
		fromVeles(hcp.NewAccessTokenValidator(), "secrets/hcpaccesstokenvalidate", 0),
		fromVeles(huggingfaceapikey.NewValidator(), "secrets/huggingfaceapikeyvalidate", 0),
		fromVeles(openai.NewProjectValidator(), "secrets/openaivalidate", 0),
		fromVeles(openrouter.NewValidator(), "secrets/openroutervalidate", 0),
		fromVeles(packagist.NewAPIKeyValidator(), "secrets/packagistapikeyvalidate", 0),
		fromVeles(packagist.NewAPISecretValidator(), "secrets/packagistsecretvalidate", 0),
		fromVeles(perplexityapikey.NewValidator(), "secrets/perplexityapikeyvalidate", 0),
		fromVeles(postmanapikey.NewAPIValidator(), "secrets/postmanapikeyvalidate", 0),
		fromVeles(postmanapikey.NewCollectionValidator(), "secrets/postmancollectiontokenvalidate", 0),
		fromVeles(github.NewAppS2STokenValidator(), "secrets/githubapps2stokenvalidate", 0),
		fromVeles(github.NewAppU2STokenValidator(), "secrets/githubappu2stokenvalidate", 0),
		fromVeles(github.NewOAuthTokenValidator(), "secrets/githuboauthtokenvalidate", 0),
		fromVeles(github.NewClassicPATValidator(), "secrets/githubclassicpatvalidate", 0),
		fromVeles(github.NewFineGrainedPATValidator(), "secrets/githubfinegrainedpatvalidate", 0),
		fromVeles(stripeapikeys.NewSecretKeyValidator(), "secrets/stripesecretkeyvalidate", 0),
		fromVeles(stripeapikeys.NewRestrictedKeyValidator(), "secrets/striperestrictedkeyvalidate", 0),
		fromVeles(gcpoauth2access.NewValidator(), "secrets/gcpoauth2accesstokenvalidate", 0),
		fromVeles(paystacksecretkey.NewValidator(), "secrets/paystacksecretkeyvalidate", 0),
		fromVeles(gcshmackey.NewValidator(), "secrets/gcshmackeyvalidate", 0),
		fromVeles(awsaccesskey.NewValidator(), "secrets/awsaccesskeyvalidate", 0),
		fromVeles(codecatalyst.NewValidator(), "secrets/codecatalystcredentialsvalidate", 0),
		fromVeles(codecommit.NewValidator(), "secrets/codecommitcredentialsvalidate", 0),
		fromVeles(bitbucket.NewValidator(), "secrets/bitbucketcredentialsvalidate", 0),
		fromVeles(telegrambotapitoken.NewValidator(), "secrets/telegrombotapitokenvalidate", 0),
		fromVeles(cursorapikey.NewValidator(), "secrets/cursorapikeyvalidate", 0),
	})

	// SecretsEnrich lists enrichers that add data to detected secrets.
	SecretsEnrich = InitMap{
		hcpidentity.Name: {noCFG(hcpidentity.New)},
	}

	// HuggingfaceMeta enricher.
	HuggingfaceMeta = InitMap{
		huggingfacemeta.Name: {noCFG(huggingfacemeta.New)},
	}

	// Reachability enrichers.
	Reachability = InitMap{
		java.Name:       {noCFG(java.NewDefault)},
		govcsource.Name: {govcsource.New},
		rust.Name:       {rust.New},
	}

	// TransitiveDependency enrichers.
	TransitiveDependency = InitMap{
		requirements.Name: {requirements.New},
		pomxml.Name:       {pomxml.New},
	}

	// PackageDeprecation enricher.
	PackageDeprecation = InitMap{
		packagedeprecation.Name: {packagedeprecation.New},
	}

	// Default enrichers.
	Default = concat()

	// All enrichers.
	All = concat(
		LayerDetails,
		VulnMatching,
		VEX,
		SecretsValidate,
		SecretsEnrich,
		HuggingfaceMeta,
		License,
		Reachability,
		TransitiveDependency,
		PackageDeprecation,
	)

	enricherNames = concat(All, InitMap{
		"license":              vals(License),
		"vex":                  vals(VEX),
		"vulnmatch":            vals(VulnMatching),
		"layerdetails":         vals(LayerDetails),
		"secretsvalidate":      vals(SecretsValidate),
		"secretsenrich":        vals(SecretsEnrich),
		"reachability":         vals(Reachability),
		"transitivedependency": vals(TransitiveDependency),
		"packagedeprecation":   vals(PackageDeprecation),

		"enrichers/default": vals(Default),
		"default":           vals(Default),
		"enrichers/all":     vals(All),
		"all":               vals(All),
	})
)

func concat(initMaps ...InitMap) InitMap {
	result := InitMap{}
	for _, m := range initMaps {
		maps.Copy(result, m)
	}
	return result
}

func vals(initMap InitMap) []InitFn {
	return slices.Concat(slices.AppendSeq(make([][]InitFn, 0, len(initMap)), maps.Values(initMap))...)
}

// Wraps initer functions that don't take any config value to initer functions that do.
// TODO(b/400910349): Remove once all plugins take config values.
func noCFG(f func() enricher.Enricher) InitFn {
	return func(_ *cpb.PluginConfig) (enricher.Enricher, error) { return f(), nil }
}

// EnricherFromName returns a single enricher based on its exact name.
func EnricherFromName(name string, cfg *cpb.PluginConfig) (enricher.Enricher, error) {
	initers, ok := enricherNames[name]
	if !ok {
		return nil, fmt.Errorf("unknown enricher %q", name)
	}
	if len(initers) != 1 {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	e, err := initers[0](cfg)
	if err != nil {
		return nil, err
	}
	if e.Name() != name {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	return e, nil
}

// EnrichersFromName returns a list of enrichers from a name.
func EnrichersFromName(name string, cfg *cpb.PluginConfig) ([]enricher.Enricher, error) {
	if initers, ok := enricherNames[name]; ok {
		var result []enricher.Enricher
		for _, initer := range initers {
			p, err := initer(cfg)
			if err != nil {
				return nil, err
			}
			result = append(result, p)
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown enricher %q", name)
}

type velesPlugin struct {
	initFunc InitFn
	name     string
}

func fromVeles[S veles.Secret](validator veles.Validator[S], name string, version int) velesPlugin {
	return velesPlugin{
		initFunc: noCFG(convert.FromVelesValidator(validator, name, version)),
		name:     name,
	}
}

func fromVelesWithCfg(initFunc InitFn, name string) velesPlugin {
	return velesPlugin{
		initFunc: initFunc,
		name:     name,
	}
}

func initMapFromVelesPlugins(plugins []velesPlugin) InitMap {
	result := InitMap{}
	for _, p := range plugins {
		result[p.name] = []InitFn{p.initFunc}
	}
	return result
}
