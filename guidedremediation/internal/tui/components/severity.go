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

package components

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/severity"
	osvpb "github.com/ossf/osv-schema/bindings/go/osvschema"
)

var (
	severityColors = map[string]lipgloss.Color{
		"UNKNOWN":  lipgloss.Color("243"), // grey
		"NONE":     lipgloss.Color("243"), // grey
		"LOW":      lipgloss.Color("28"),  // green
		"MEDIUM":   lipgloss.Color("208"), // orange
		"HIGH":     lipgloss.Color("160"), // red
		"CRITICAL": lipgloss.Color("88"),  // dark red
	}
	severityStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("15")). // white
			Bold(true).
			Align(lipgloss.Center)
)

// RenderSeverity renders for terminal the highest severity score & rating of a list of severities.
func RenderSeverity(severities []*osvpb.Severity) string {
	text := "UNKNOWN"
	bestScore := -1.0
	for _, sev := range severities {
		score, rating, err := severity.CalculateScoreAndRating(sev)
		if err != nil || score <= bestScore {
			continue
		}
		bestScore = score
		if rating != "UNKNOWN" {
			text = fmt.Sprintf("%1.1f %s", score, rating)
		}
	}
	return severityStyle.Width(16).Background(severityColors[text]).Render(text)
}

// RenderSeverityShort renders for terminal the highest severity score only of a list of severities.
func RenderSeverityShort(severities []*osvpb.Severity) string {
	bestScore := -1.0
	bestRating := "UNKNOWN"
	for _, sev := range severities {
		score, rating, err := severity.CalculateScoreAndRating(sev)
		if err != nil || score <= bestScore {
			continue
		}
		bestScore = score
		bestRating = rating
	}
	str := "???"
	if bestScore >= 0 {
		str = fmt.Sprintf("%1.1f", bestScore)
	}
	return severityStyle.Width(5).Background(severityColors[bestRating]).Render(str)
}
