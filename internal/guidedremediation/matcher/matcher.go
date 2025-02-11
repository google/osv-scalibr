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

// Package matcher provides the interface for the vulnerability matcher used by guided remediation.
package matcher

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
)

// TODO(#454): Temporarily internal while migration is in progress.
// Will need to be moved to publicly accessible location once external interface is created.

// VulnerabilityMatcher interface provides functionality get a list of affecting vulnerabilities for each package in an inventory.
type VulnerabilityMatcher interface {
	MatchVulnerabilities(ctx context.Context, invs []*extractor.Inventory) ([][]*OSVRecord, error)
}

// OSVRecord is a representation of an OSV record.
// TODO: replace with https://github.com/ossf/osv-schema/pull/333
type OSVRecord struct {
	ID       string `yaml:"id"`
	Affected []struct {
		Package struct {
			Ecosystem string `yaml:"ecosystem,omitempty"`
			Name      string `yaml:"name,omitempty"`
		} `yaml:"package,omitempty"`
		Ranges []struct {
			Type   string     `yaml:"type,omitempty"`
			Events []OSVEvent `yaml:"events,omitempty"`
		} `yaml:"ranges,omitempty"`
		Versions []string `yaml:"versions,omitempty"`
	} `yaml:"affected,omitempty"`
}

type OSVEvent struct {
	Introduced   string `yaml:"introduced,omitempty"`
	Fixed        string `yaml:"fixed,omitempty"`
	LastAffected string `yaml:"last_affected,omitempty"`
}
