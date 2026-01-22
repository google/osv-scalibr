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

// Package rpm implements an annotator for language packages that have already been found in
// RPM OS packages.
package rpm

import (
	"time"

	"github.com/google/osv-scalibr/annotator"
	cpb "github.com/google/osv-scalibr/binary/proto/config_go_proto"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name = "vex/os-duplicate/rpm"

	defaultTimeout = 5 * time.Minute
)

// Annotator adds annotations to language packages that have already been found in RPM OS packages.
type Annotator struct {
	Timeout time.Duration
}

// New returns a new Annotator.
func New(cfg *cpb.PluginConfig) (annotator.Annotator, error) {
	timeout := defaultTimeout

	specific := plugin.FindConfig(cfg, func(c *cpb.PluginSpecificConfig) *cpb.RpmConfig { return c.GetRpm() })
	if specific.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(specific.GetTimeoutSeconds()) * time.Second
	}

	return &Annotator{Timeout: timeout}, nil
}

// Name of the annotator.
func (Annotator) Name() string { return Name }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}
