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

// Package client provides interfaces for the clients used by guided remediation.
package client

import (
	"context"

	"github.com/google/osv-scalibr/extractor"
)

// Temporarily internal while migration is in progress.
// Will need to be moved to publicly accessible location once external interface is created.

// VulnerabilityMatcher interface provides functionality get a list of affecting vulnerabilities for each package in an inventory.
type VulnerabilityMatcher interface {
	MatchVulnerabilities(ctx context.Context, invs []*extractor.Inventory) ([][]*OSVRecord, error)
}

// OSVRecord is a representation of an OSV record.
// TODO: replace with https://github.com/ossf/osv-schema/pull/333
type OSVRecord struct {
	ID string
}
