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
	"github.com/google/osv-scalibr/enricher/huggingfacemeta"
	"github.com/google/osv-scalibr/enricher/license"
	"github.com/google/osv-scalibr/enricher/reachability/java"
	"github.com/google/osv-scalibr/enricher/secrets/convert"
	"github.com/google/osv-scalibr/enricher/transitivedependency/requirements"
	"github.com/google/osv-scalibr/enricher/vex/filter"
	"github.com/google/osv-scalibr/enricher/vulnmatch/osvdev"
	"github.com/google/osv-scalibr/veles"
	"github.com/google/osv-scalibr/veles/secrets/anthropicapikey"
	"github.com/google/osv-scalibr/veles/secrets/digitaloceanapikey"
	"github.com/google/osv-scalibr/veles/secrets/dockerhubpat"
	"github.com/google/osv-scalibr/veles/secrets/gcpsak"
	"github.com/google/osv-scalibr/veles/secrets/gitlabpat"
	"github.com/google/osv-scalibr/veles/secrets/grokxaiapikey"
	"github.com/google/osv-scalibr/veles/secrets/huggingfaceapikey"
	"github.com/google/osv-scalibr/veles/secrets/openai"
	"github.com/google/osv-scalibr/veles/secrets/perplexityapikey"
	"github.com/google/osv-scalibr/veles/secrets/postmanapikey"
	"github.com/google/osv-scalibr/veles/secrets/stripeapikeys"
)

// InitFn is the enricher initializer function.
type InitFn func() enricher.Enricher

// InitMap is a map of names to enricher initializer functions.
type InitMap map[string][]InitFn

var (

	// LayerDetails enrichers.
	LayerDetails = InitMap{
		baseimage.Name: {baseimage.NewDefault},
	}

	// License enrichers.
	License = InitMap{
		license.Name: {license.New},
	}

	// VulnMatching enrichers.
	VulnMatching = InitMap{

		osvdev.Name: {osvdev.NewDefault},
	}

	// VEX related enrichers.
	VEX = InitMap{
		filter.Name: {filter.New},
	}

	// Secrets enrichers.
	Secrets = initMapFromVelesPlugins([]velesPlugin{
		fromVeles(anthropicapikey.NewWorkspaceValidator(), "secrets/anthropicapikeyworkspacevalidate", 0),
		fromVeles(anthropicapikey.NewModelValidator(), "secrets/anthropicapikeymodelvalidate", 0),
		fromVeles(digitaloceanapikey.NewValidator(), "secrets/digitaloceanapikeyvalidate", 0),
		fromVeles(dockerhubpat.NewValidator(), "secrets/dockerhubpatvalidate", 0),
		fromVeles(gcpsak.NewValidator(), "secrets/gcpsakvalidate", 0),
		fromVeles(gitlabpat.NewValidator(), "secrets/gitlabpatvalidate", 0),
		fromVeles(grokxaiapikey.NewAPIValidator(), "secrets/grokxaiapikeyvalidate", 0),
		fromVeles(grokxaiapikey.NewManagementAPIValidator(), "secrets/grokxaimanagementkeyvalidate", 0),
		fromVeles(huggingfaceapikey.NewValidator(), "secrets/huggingfaceapikeyvalidate", 0),
		fromVeles(openai.NewProjectValidator(), "secrets/openaivalidate", 0),
		fromVeles(perplexityapikey.NewValidator(), "secrets/perplexityapikeyvalidate", 0),
		fromVeles(postmanapikey.NewAPIValidator(), "secrets/postmanapikeyvalidate", 0),
		fromVeles(postmanapikey.NewCollectionValidator(), "secrets/postmancollectiontokenvalidate", 0),
		fromVeles(stripeapikeys.NewSecretKeyValidator(), "secrets/stripesecretkeyvalidate", 0),
		fromVeles(stripeapikeys.NewRestrictedKeyValidator(), "secrets/striperestrictedkeyvalidate", 0),
	})

	// HuggingfaceMeta enricher.
	HuggingfaceMeta = InitMap{
		huggingfacemeta.Name: {huggingfacemeta.New},
	}

	// Reachability enrichers.
	Reachability = InitMap{
		java.Name: {java.NewDefault},
	}

	// TransitiveDependency enrichers.
	TransitiveDependency = InitMap{
		requirements.Name: {requirements.NewDefault},
	}

	// Default enrichers.
	Default = concat()

	// All enrichers.
	All = concat(
		LayerDetails,
		VulnMatching,
		VEX,
		Secrets,
		HuggingfaceMeta,
		License,
		Reachability,
		TransitiveDependency,
	)

	enricherNames = concat(All, InitMap{
		"license":              vals(License),
		"vex":                  vals(VEX),
		"vulnmatch":            vals(VulnMatching),
		"layerdetails":         vals(LayerDetails),
		"secretsvalidate":      vals(Secrets),
		"reachability":         vals(Reachability),
		"transitivedependency": vals(TransitiveDependency),
		"enrichers/default":    vals(Default),
		"default":              vals(Default),
		"enrichers/all":        vals(All),
		"all":                  vals(All),
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

// EnricherFromName returns a single enricher based on its exact name.
func EnricherFromName(name string) (enricher.Enricher, error) {
	initers, ok := enricherNames[name]
	if !ok {
		return nil, fmt.Errorf("unknown enricher %q", name)
	}
	if len(initers) != 1 {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	e := initers[0]()
	if e.Name() != name {
		return nil, fmt.Errorf("not an exact name for an enricher: %s", name)
	}
	return e, nil
}

// EnrichersFromName returns a list of enrichers from a name.
func EnrichersFromName(name string) ([]enricher.Enricher, error) {
	if initers, ok := enricherNames[name]; ok {
		result := []enricher.Enricher{}
		for _, initer := range initers {
			result = append(result, initer())
		}
		return result, nil
	}
	return nil, fmt.Errorf("unknown enricher %q", name)
}

type velesPlugin struct {
	initFunc func() enricher.Enricher
	name     string
}

func fromVeles[S veles.Secret](validator veles.Validator[S], name string, version int) velesPlugin {
	return velesPlugin{
		initFunc: convert.FromVelesValidator(validator, name, version),
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
