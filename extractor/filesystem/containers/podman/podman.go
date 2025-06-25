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

// Package podman extracts container inventory from podman database.
package podman

import (
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name is the unique name of this extractor.
	Name = "containers/podman"
)

// Config defines the configuration options for the Extractor.
type Config struct {
	// IncludeStopped specifies whether to list all containers, including those that are not currently running.
	IncludeStopped bool
}

// DefaultConfig returns the default configuration for the podman extractor.
func DefaultConfig() Config {
	return Config{}
}

// Extractor extracts containers from the podman db file.
type Extractor struct {
	cfg Config
}

// New returns a podman container inventory extractor.
func New(cfg Config) *Extractor {
	return &Extractor{cfg: cfg}
}

// NewDefault returns an extractor with the default config settings.
func NewDefault() filesystem.Extractor { return New(DefaultConfig()) }

// Config returns the configuration of the extractor.
func (e Extractor) Config() Config {
	return Config{}
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
