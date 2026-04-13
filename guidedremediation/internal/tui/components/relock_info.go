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
	"slices"
	"strings"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/result"
)

// relockInfo is a ViewModel showing the dependency changes, the removed, and added vulnerabilities
// resulting from a proposed relock patch
type relockInfo struct {
	fixedHeight  float64
	fixedList    *vulnList
	addedList    *vulnList
	addedFocused bool
}

// NewRelockInfo creates a ViewModel showing the dependency changes, the removed, and added vulnerabilities
// resulting from a proposed relock patch.
// allVulns must contain all vulnerabilities, both before and after patch application.
func NewRelockInfo(patch result.Patch, allVulns []resolution.Vulnerability, detailsRenderer DetailsRenderer) ViewModel {
	info := relockInfo{fixedHeight: 1}
	preamble := strings.Builder{}
	preamble.WriteString("The following upgrades:\n")
	for _, pkg := range patch.PackageUpdates {
		fmt.Fprintf(&preamble, "  %s@%s → @%s\n", pkg.Name, pkg.VersionFrom, pkg.VersionTo)
	}
	preamble.WriteString("Will resolve the following:")
	fixedVulns := make([]resolution.Vulnerability, 0, len(patch.Fixed))
	for _, fixed := range patch.Fixed {
		idx := slices.IndexFunc(allVulns, func(v resolution.Vulnerability) bool { return v.OSV.Id == fixed.ID })
		if idx >= 0 {
			fixedVulns = append(fixedVulns, allVulns[idx])
		}
		// else, something went wrong, just ignore this.
	}
	info.fixedList = NewVulnList(fixedVulns, preamble.String(), detailsRenderer).(*vulnList)

	if len(patch.Introduced) == 0 {
		return &info
	}

	// Create a second list showing introduced vulns
	newVulns := make([]resolution.Vulnerability, 0, len(patch.Introduced))
	for i := range patch.Introduced {
		idx := slices.IndexFunc(allVulns, func(v resolution.Vulnerability) bool { return v.OSV.Id == patch.Introduced[i].ID })
		if idx >= 0 {
			newVulns = append(newVulns, allVulns[idx])
		}
		// else, something went wrong, just ignore this.
	}
	info.addedList = NewVulnList(newVulns, "But will introduce the following new vulns:", detailsRenderer).(*vulnList)
	info.addedList.Blur()

	// divide two lists by roughly how many lines each would have
	const fixedMinHeight = 0.5
	const fixedMaxHeight = 0.8
	fixed := float64(len(patch.PackageUpdates) + len(fixedVulns))
	added := float64(len(newVulns))
	info.fixedHeight = fixed / (fixed + added)
	if info.fixedHeight < fixedMinHeight {
		info.fixedHeight = fixedMinHeight
	}
	if info.fixedHeight > fixedMaxHeight {
		info.fixedHeight = fixedMaxHeight
	}

	return &info
}

func (r *relockInfo) Resize(w, h int) ViewModel {
	fixedHeight := int(r.fixedHeight * float64(h))
	r.fixedList = r.fixedList.Resize(w, fixedHeight).(*vulnList)
	if r.addedList != nil {
		r.addedList = r.addedList.Resize(w, h-fixedHeight).(*vulnList)
	}

	return r
}

func (r *relockInfo) Update(msg tea.Msg) (ViewModel, tea.Cmd) {
	var cmds []tea.Cmd

	// check if we're trying to scroll past the end of one of the lists
	if msg, ok := msg.(tea.KeyMsg); ok && r.addedList != nil {
		// scrolling up out of the added list
		if r.addedFocused &&
			r.addedList.Index() == 0 &&
			key.Matches(msg, Keys.Up) {
			r.addedFocused = false
			r.addedList.Blur()
			r.fixedList.Focus()

			return r, nil
		}
		// scrolling down out of fixed list
		if !r.addedFocused &&
			r.fixedList.Index() == len(r.fixedList.Items())-1 &&
			key.Matches(msg, Keys.Down) {
			r.addedFocused = true
			r.addedList.Focus()
			r.fixedList.Blur()

			return r, nil
		}
	}

	// do normal updates
	l, cmd := r.fixedList.Update(msg)
	r.fixedList = l.(*vulnList)
	cmds = append(cmds, cmd)

	if r.addedList != nil {
		l, cmd := r.addedList.Update(msg)
		r.addedList = l.(*vulnList)
		cmds = append(cmds, cmd)
	}

	return r, tea.Batch(cmds...)
}

func (r *relockInfo) View() string {
	if r.addedList == nil || r.fixedList.currVulnInfo != nil {
		return r.fixedList.View()
	}
	if r.addedList.currVulnInfo != nil {
		return r.addedList.View()
	}

	return lipgloss.JoinVertical(lipgloss.Center, r.fixedList.View(), r.addedList.View())
}
