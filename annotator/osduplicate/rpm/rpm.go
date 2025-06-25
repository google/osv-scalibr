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

// Package rpm implements an annotator for language packages that have already been found in
// RPM OS packages.
package rpm

import (
	"time"

	"github.com/google/osv-scalibr/annotator"
	"github.com/google/osv-scalibr/plugin"
)

const (
	// Name of the Annotator.
	Name = "vex/os-duplicate/rpm"

	defaultTimeout = 5 * time.Minute
)

// Config contains RPM specific configuration values
type Config struct {
	// Timeout is the timeout duration for parsing the RPM database.
	Timeout time.Duration
}

// DefaultConfig returns the default configuration values for the Annotator.
func DefaultConfig() Config {
	return Config{
		Timeout: defaultTimeout,
	}
}

// Annotator adds annotations to language packages that have already been found in RPM OS packages.
type Annotator struct {
	Timeout time.Duration
}

// New returns a new Annotator.
//
// For most use cases, initialize with:
// ```
// a := New(DefaultConfig())
// ```
func New(cfg Config) *Annotator {
	return &Annotator{
		Timeout: cfg.Timeout,
	}
}

// NewDefault returns the Annotator with the default config settings.
func NewDefault() annotator.Annotator { return New(DefaultConfig()) }

// Name of the annotator.
func (Annotator) Name() string { return Name }

// Version of the annotator.
func (Annotator) Version() int { return 0 }

// Requirements of the annotator.
func (Annotator) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{OS: plugin.OSLinux}
}
