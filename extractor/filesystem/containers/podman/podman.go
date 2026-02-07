// Copyright 2026 Google LLC
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

// Package podman extracts container inventory from podman database.
package podman

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"

	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/podman"
)

// Extractor extracts containers from the podman db file.
type Extractor struct {
	IncludeStopped bool
}

// New returns a podman container inventory extractor.
func New(cfg *cpb.PluginConfig) (filesystem.Extractor, error) {
	includeStopped := false
	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.PodmanConfig { return c.GetPodman() })
	if specific != nil {
		includeStopped = specific.GetIncludeStopped()
	}

	return &Extractor{IncludeStopped: includeStopped}, nil
}

// Name of the extractor.
func (e Extractor) Name() string { return Name }

// Version of the extractor.
func (e Extractor) Version() int { return 0 }

// Requirements of the extractor.
func (e Extractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{
		OS:            plugin.OSLinux,
		DirectFS:      true,
		RunningSystem: true,
	}
}
