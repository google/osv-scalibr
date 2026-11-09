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
	"strings"
	"time"

	"github.com/CycloneDX/cyclonedx-go"
	"github.com/google/osv-scalibr/internal/severity"
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

var cdxScoringMapper = map[osvpb.Severity_Type]cyclonedx.ScoringMethod{
	osvpb.Severity_CVSS_V2: cyclonedx.ScoringMethodCVSSv2,
	osvpb.Severity_CVSS_V3: cyclonedx.ScoringMethodCVSSv3,
	osvpb.Severity_CVSS_V4: cyclonedx.ScoringMethodCVSSv4,
}

var cdxSeverityMapper = map[string]cyclonedx.Severity{
	"critical": cyclonedx.SeverityCritical,
	"high":     cyclonedx.SeverityHigh,
	"medium":   cyclonedx.SeverityMedium,
	"low":      cyclonedx.SeverityLow,
	"none":     cyclonedx.SeverityNone,
}

func buildCDXRatings(vuln *osvpb.Vulnerability) *[]cyclonedx.VulnerabilityRating {
	var ratings []cyclonedx.VulnerabilityRating

	for _, sev := range vuln.GetSeverity() {
		// skip severities that cdx does not support
		method, ok := cdxScoringMapper[sev.GetType()]
		if !ok {
			continue
		}

		// there is nothing to rate without a vector
		if sev.GetScore() == "" {
			continue
		}

		cdxRating := cyclonedx.VulnerabilityRating{
			Method: method,
			Vector: sev.GetScore(),
		}

		// keep the vector even if it cannot be scored, so the data is not lost
		if score, rating, err := severity.CalculateScoreAndRating(sev); err == nil {
			cdxRating.Score = &score
			cdxRating.Severity = cdxSeverityMapper[strings.ToLower(rating)]
		}

		ratings = append(ratings, cdxRating)
	}

	if len(ratings) == 0 {
		return nil
	}

	return &ratings
}

func buildCDXAdvisories(vuln *osvpb.Vulnerability) *[]cyclonedx.Advisory {
	var advisories []cyclonedx.Advisory

	for _, reference := range vuln.GetReferences() {
		if reference.GetType() != osvpb.Reference_ADVISORY {
			continue
		}
		advisories = append(advisories, cyclonedx.Advisory{
			URL: reference.GetUrl(),
		})
	}

	if len(advisories) == 0 {
		return nil
	}

	return &advisories
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
			Name:  credit.GetName(),
			Email: firstEmail(credit.GetContact()),
		})
	}

	if len(*credits.Individuals) == 0 {
		return nil
	}

	return credits
}

// firstEmail returns the first contact url that begins with "mailto:"
// without the prefix, if any
func firstEmail(contacts []string) string {
	for _, contact := range contacts {
		if email, ok := strings.CutPrefix(contact, "mailto:"); ok {
			return email
		}
	}

	return ""
}
