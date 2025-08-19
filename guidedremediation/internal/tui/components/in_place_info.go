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

package components

import (
	"fmt"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// inPlaceInfo is a ViewModel showing the table of package upgrades and fixed vulnerabilities,
// for in-place upgrades.
// Pressing 'enter' on a row shows the vulnerability details.
type inPlaceInfo struct {
	table.Model

	vulns           []resolution.Vulnerability
	detailsRenderer DetailsRenderer // renderer for markdown details.
	currVulnInfo    ViewModel

	width  int
	height int
}

// NewInPlaceInfo creates a ViewModel showing the table of package upgrades and fixed vulnerabilities,
// for in-place upgrades.
func NewInPlaceInfo(patches []result.Patch, vulns []resolution.Vulnerability, detailsRenderer DetailsRenderer) ViewModel {
	info := inPlaceInfo{
		vulns:           vulns,
		detailsRenderer: detailsRenderer,
		width:           ViewMinWidth,
		height:          ViewMinHeight,
	}

	cols := []table.Column{
		{Title: "PACKAGE"},
		{Title: "VERSION CHANGE"},
		{Title: "FIXED VULN"},
	}
	for i := range cols {
		cols[i].Width = lipgloss.Width(cols[i].Title)
	}

	// Have 1 row per vulnerability, but only put the package name on the first vuln it fixes.
	rows := make([]table.Row, 0, len(vulns))
	for _, p := range patches {
		row := table.Row{
			p.PackageUpdates[0].Name,
			fmt.Sprintf("%s → %s", p.PackageUpdates[0].VersionFrom, p.PackageUpdates[0].VersionTo),
			p.Fixed[0].ID,
		}
		// Set each column to their widest element
		for i, s := range row {
			if w := lipgloss.Width(s); w > cols[i].Width {
				cols[i].Width = w
			}
		}
		rows = append(rows, row)

		// use blank package name / bump for other vulns from same patch
		for _, v := range p.Fixed[1:] {
			row := table.Row{
				"",
				"",
				v.ID,
			}
			rows = append(rows, row)
			if w := lipgloss.Width(row[2]); w > cols[2].Width {
				cols[2].Width = w
			}
		}
	}

	// center the version change column
	cols[1].Title = lipgloss.PlaceHorizontal(cols[1].Width, lipgloss.Center, cols[1].Title)
	for _, row := range rows {
		row[1] = lipgloss.PlaceHorizontal(cols[1].Width, lipgloss.Center, row[1])
	}

	st := table.DefaultStyles()
	st.Header = st.Header.Bold(false).BorderStyle(lipgloss.NormalBorder()).BorderBottom(true)
	st.Selected = st.Selected.Foreground(ColorPrimary)

	info.Model = table.New(
		table.WithColumns(cols),
		table.WithRows(rows),
		table.WithWidth(info.width),
		table.WithHeight(info.height),
		table.WithFocused(true),
		table.WithStyles(st),
		table.WithKeyMap(table.KeyMap{
			LineUp:   Keys.Up,
			LineDown: Keys.Down,
			PageUp:   Keys.Left,
			PageDown: Keys.Right,
		}),
	)

	return &info
}

func (ip *inPlaceInfo) Resize(w, h int) ViewModel {
	ip.width = w
	ip.height = h
	ip.SetWidth(w)
	ip.SetHeight(h)
	if ip.currVulnInfo != nil {
		ip.currVulnInfo.Resize(w, h)
	}

	return ip
}

func (ip *inPlaceInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	var cmd tea.Cmd
	if ip.currVulnInfo != nil {
		ip.currVulnInfo, cmd = ip.currVulnInfo.Update(msg)
		return ip, cmd
	}
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, Keys.Quit):
			return ip, CloseViewModel
		case key.Matches(msg, Keys.Select):
			vID := ip.Rows()[ip.Cursor()][2]
			vIdx := slices.IndexFunc(ip.vulns, func(v resolution.Vulnerability) bool { return v.OSV.ID == vID })
			if vIdx == -1 {
				// something went wrong, just ignore this.
				return ip, nil
			}
			vuln := ip.vulns[vIdx]
			ip.currVulnInfo = NewVulnInfo(vuln, ip.detailsRenderer)
			ip.currVulnInfo = ip.currVulnInfo.Resize(ip.Width(), ip.Height())

			return ip, nil
		}
	}
	ip.Model, cmd = ip.Model.Update(msg)

	return ip, cmd
}

func (ip *inPlaceInfo) View() string {
	if ip.currVulnInfo != nil {
		return ip.currVulnInfo.View()
	}
	// place the table in the center of the view
	return lipgloss.Place(ip.width, ip.height, lipgloss.Center, lipgloss.Center, ip.Model.View())
}

// GetModel returns the underlying table model.
// This is used by the in-place patches state to get the table model.
func (ip *inPlaceInfo) GetModel() table.Model {
	return ip.Model
}
