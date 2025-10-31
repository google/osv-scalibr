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
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

// VulnerabilityMatcher interface provides functionality get a list of affecting vulnerabilities for each package in an inventory.
type VulnerabilityMatcher interface {
	MatchVulnerabilities(ctx context.Context, pkgs []*extractor.Package) ([][]*osvpb.Vulnerability, error)
}
