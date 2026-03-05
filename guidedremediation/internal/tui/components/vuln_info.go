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
	"strings"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/muesli/reflow/wordwrap"
)

// vulnInfo is a ViewModel to display the details of a specific vulnerability
type vulnInfo struct {
	vuln        resolution.Vulnerability
	chainGraphs []ChainGraph

	width  int
	height int
	cursor int

	numDetailLines  int             // number of lines to show for details in the main view
	detailsRenderer DetailsRenderer // renderer for markdown details.

	viewport    viewport.Model // used for scrolling onlyDetails & onlyGraphs views
	onlyDetails bool           // if the details screen is open
	onlyGraphs  bool           // if the affected screen is open
}

var (
	vulnInfoHeadingStyle = lipgloss.NewStyle().
				Bold(true).
				Width(10).
				MarginRight(2).
				Foreground(ColorPrimary)
	highlightedVulnInfoHeadingStyle = vulnInfoHeadingStyle.Reverse(true)
)

// NewVulnInfo creates a ViewModel to display the details of a specific vulnerability.
func NewVulnInfo(vuln resolution.Vulnerability, detailsRenderer DetailsRenderer) ViewModel {
	v := vulnInfo{
		vuln:            vuln,
		width:           ViewMinWidth,
		height:          ViewMinHeight,
		cursor:          0,
		numDetailLines:  5,
		viewport:        viewport.New(ViewMinWidth, 20),
		detailsRenderer: detailsRenderer,
	}
	v.viewport.KeyMap = viewport.KeyMap{
		Up:       Keys.Up,
		Down:     Keys.Down,
		PageUp:   Keys.Left,
		PageDown: Keys.Right,
	}

	v.chainGraphs = FindChainGraphs(vuln.Subgraphs)

	return &v
}

func (v *vulnInfo) Resize(w, h int) ViewModel {
	v.width = w
	v.height = h
	v.viewport.Width = w
	v.viewport.Height = h
	if v.onlyDetails {
		v.viewport.SetContent(v.detailsOnlyView())
	}
	return v
}

func (v *vulnInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	if v.onlyDetails || v.onlyGraphs {
		if msg, ok := msg.(tea.KeyMsg); ok {
			if key.Matches(msg, Keys.Quit) {
				v.onlyDetails = false
				v.onlyGraphs = false

				return v, nil
			}
		}
		var cmd tea.Cmd
		v.viewport, cmd = v.viewport.Update(msg)

		return v, cmd
	}
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, Keys.Quit):
			return nil, nil
		case key.Matches(msg, Keys.Down):
			if v.cursor < 4 {
				v.cursor++
			}
		case key.Matches(msg, Keys.Up):
			if v.cursor > 0 {
				v.cursor--
			}
		case key.Matches(msg, Keys.Select):
			if v.cursor == 3 {
				v.onlyDetails = true
				v.viewport.SetContent(v.detailsOnlyView())
				v.viewport.GotoTop()
			}
			if v.cursor == 4 {
				v.onlyGraphs = true
				v.viewport.SetContent(v.graphOnlyView())
				v.viewport.GotoTop()
			}
		}
	}

	return v, nil
}

func (v *vulnInfo) View() string {
	if v.onlyDetails || v.onlyGraphs {
		return v.viewport.View()
	}

	detailWidth := v.width - (vulnInfoHeadingStyle.GetWidth() + vulnInfoHeadingStyle.GetMarginRight())

	vID := v.vuln.OSV.Id
	sev := RenderSeverity(v.vuln.OSV.Severity)
	sum := wordwrap.String(v.vuln.OSV.Summary, detailWidth)

	det, err := v.detailsRenderer.Render(v.vuln.OSV.Details, v.width)
	if err != nil {
		det, _ = FallbackDetailsRenderer{}.Render(v.vuln.OSV.Details, v.width)
	}
	det = lipgloss.NewStyle().MaxHeight(v.numDetailLines).Render(det)

	s := strings.Builder{}
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(0).Render("ID:"), vID))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(1).Render("Severity:"), sev))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(2).Render("Summary:"), sum))
	s.WriteString("\n")
	s.WriteString(lipgloss.JoinHorizontal(lipgloss.Top,
		v.headingStyle(3).Render("Details:"), det))
	s.WriteString("\n")
	s.WriteString(v.headingStyle(4).Render("Affected:"))
	s.WriteString("\n")
	if len(v.chainGraphs) == 0 {
		s.WriteString("ERROR: could not resolve any affected paths\n")
		return s.String()
	}
	s.WriteString(lipgloss.NewStyle().MaxWidth(v.width).Render(v.chainGraphs[0].String()))
	s.WriteString("\n")
	if len(v.chainGraphs) > 1 {
		s.WriteString(DisabledTextStyle.Render(fmt.Sprintf("+%d other paths", len(v.chainGraphs)-1)))
		s.WriteString("\n")
	}

	return s.String()
}

func (v *vulnInfo) detailsOnlyView() string {
	s := strings.Builder{}
	s.WriteString(vulnInfoHeadingStyle.Render("Details:"))
	s.WriteString("\n")
	var det string
	det, err := v.detailsRenderer.Render(v.vuln.OSV.Details, v.width)
	if err != nil {
		det, _ = FallbackDetailsRenderer{}.Render(v.vuln.OSV.Details, v.width)
	}
	s.WriteString(det)

	return s.String()
}

func (v *vulnInfo) graphOnlyView() string {
	// Annoyingly, some graphs still get clipped on the right side.
	// This needs horizontal scrolling, but that's not supported by the bubbles viewport
	// and it's difficult to implement
	s := strings.Builder{}
	s.WriteString(vulnInfoHeadingStyle.Render("Affected:"))
	strs := make([]string, 0, 2*len(v.chainGraphs)) // 2x to include padding newlines between graphs
	for _, g := range v.chainGraphs {
		strs = append(strs, "\n", g.String())
	}
	s.WriteString(lipgloss.JoinVertical(lipgloss.Center, strs...))

	return s.String()
}

func (v *vulnInfo) headingStyle(idx int) lipgloss.Style {
	if idx == v.cursor {
		return highlightedVulnInfoHeadingStyle
	}

	return vulnInfoHeadingStyle
}

// DetailsRenderer is an interface for rendering the markdown details of an OSV record.
type DetailsRenderer interface {
	Render(details string, width int) (string, error)
}

// FallbackDetailsRenderer is a DetailsRenderer that renders the details as-is (without markdown).
type FallbackDetailsRenderer struct{}

// Render renders the details as-is (without markdown).
func (FallbackDetailsRenderer) Render(details string, width int) (string, error) {
	return wordwrap.String(details, width), nil
}
