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

package converter

import (
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func formatDateIfExists(ts *timestamppb.Timestamp) string {
	if ts == nil {
		return ""
	}

	return ts.AsTime().Format(time.RFC3339)
}

func buildCDXReferences(vuln *osvpb.Vulnerability) *[]cyclonedx.VulnerabilityReference {
	aliases := vuln.GetAliases()

	if len(aliases) == 0 {
		return nil
	}

	references := make([]cyclonedx.VulnerabilityReference, len(aliases))

	for i, alias := range aliases {
		references[i] = cyclonedx.VulnerabilityReference{
			ID:     alias,
			Source: &cyclonedx.Source{},
		}
	}

	return &references
}

func buildCDXCredits(vuln *osvpb.Vulnerability) *cyclonedx.Credits {
	credits := &cyclonedx.Credits{Individuals: &[]cyclonedx.OrganizationalContact{}}

	for _, credit := range vuln.GetCredits() {
		// tools are not people or organisations
		if credit.GetType() == osvpb.Credit_TOOL {
			continue
		}

		// TODO: decide on if we do "Individuals" or "Organisations"
		//  (osv does not provide a way to distinguish)
		*credits.Individuals = append(*credits.Individuals, cyclonedx.OrganizationalContact{
			Name: credit.GetName(),
		})
	}

	if len(*credits.Individuals) == 0 {
		return nil
	}

	return credits
}
