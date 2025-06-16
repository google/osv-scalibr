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

package model

import (
	"errors"
	"fmt"
	"slices"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/google/osv-scalibr/guidedremediation/internal/resolution"
	"github.com/google/osv-scalibr/guidedremediation/internal/tui/components"
)

type stateChooseInPlacePatches struct {
	stateInPlace stateInPlaceResult

	table      table.Model            // in-place table to render
	patchIdx   []int                  // for each flattened patch, its index into unflattened patches
	vulnsInfos []components.ViewModel // vulns info views corresponding to each flattened patch

	focusedInfo components.ViewModel // the infoview that is currently focused, nil if not focused

	viewWidth int // width for rendering (same as model.mainViewWidth)
}

func newStateChooseInPlacePatches(m Model, inPlaceState stateInPlaceResult) stateChooseInPlacePatches {
	s := stateChooseInPlacePatches{
		stateInPlace: inPlaceState,
	}

	// pre-computation of flattened patches and vulns
	for idx, p := range m.lockfilePatches {
		for _, fixedVuln := range p.Fixed {
			s.patchIdx = append(s.patchIdx, idx)
			vulnIdx := slices.IndexFunc(m.lockfileGraph.Vulns, func(v resolution.Vulnerability) bool { return v.OSV.ID == fixedVuln.ID })
			if vulnIdx == -1 {
				// something went wrong, just ignore this.
				s.vulnsInfos = append(s.vulnsInfos, components.TextView(""))
			} else {
				s.vulnsInfos = append(s.vulnsInfos, components.NewVulnInfo(m.lockfileGraph.Vulns[vulnIdx], m.detailsRenderer))
			}
		}
	}

	// Grab the table out of the InPlaceInfo, so it looks consistent.
	// This is quite hacky.
	c := components.NewInPlaceInfo(m.lockfilePatches, m.lockfileGraph.Vulns, m.detailsRenderer)
	t, ok := c.(interface{ GetModel() table.Model })
	if !ok {
		errorAndExit(m, errors.New("failed to get table model from in-place info"))
	}
	s.table = t.GetModel()
	// insert the select/deselect all row, and a placeholder row for the 'done' line
	r := s.table.Rows()
	r = slices.Insert(r, 0, table.Row{"", "", ""})
	r = append(r, table.Row{"", "", ""})
	s.table.SetRows(r)
	s = s.updateTableRows(m)
	s = s.Resize(m.viewWidth, m.viewHeight).(stateChooseInPlacePatches)
	s = s.ResizeInfo(m.viewWidth, m.viewHeight).(stateChooseInPlacePatches)

	return s
}

func (st stateChooseInPlacePatches) Init(m Model) tea.Cmd {
	return nil
}

func (st stateChooseInPlacePatches) Update(m Model, msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	if msg, ok := msg.(tea.KeyMsg); ok {
		switch {
		case key.Matches(msg, components.Keys.SwitchView):
			if st.IsInfoFocused() {
				st.focusedInfo = nil
				st.table.Focus()
			} else if view, canFocus := st.currentInfoView(); canFocus {
				st.focusedInfo = view
				st.table.Blur() // ignore key presses when the info view is focused
			}
		case st.IsInfoFocused():
			st.focusedInfo, cmd = st.focusedInfo.Update(msg)
			// VulnInfo returns nil as the model when it wants to exit, instead of the CloseViewModel Cmd
			// if it quits, we need to re-focus the table
			if st.focusedInfo == nil {
				st.table.Focus()
			}
		case key.Matches(msg, components.Keys.Quit):
			// go back to in-place results
			m.st = st.stateInPlace
			return m, nil

		case key.Matches(msg, components.Keys.Select):
			if st.table.Cursor() == len(st.table.Rows())-1 { // hit enter on done line
				// go back to in-place results
				m.st = st.stateInPlace
				return m, nil
			}
			if st.table.Cursor() == 0 { // select/deselect all
				// if nothing is selected, set everything to true, otherwise set everything to false
				selection := !slices.Contains(st.stateInPlace.selectedChanges, true)
				for i := range st.stateInPlace.selectedChanges {
					st.stateInPlace.selectedChanges[i] = selection
				}
			} else {
				st = st.toggleSelection(st.table.Cursor() - 1)
			}
			st = st.updateTableRows(m)
		}
	}
	// update the table
	t, c := st.table.Update(msg)
	st.table = t
	m.st = st

	return m, tea.Batch(cmd, c)
}

func (st stateChooseInPlacePatches) View(m Model) string {
	tableStr := lipgloss.PlaceHorizontal(st.viewWidth, lipgloss.Center, st.table.View())
	return lipgloss.JoinVertical(lipgloss.Left,
		tableStr,
		components.RenderSelectorOption(st.table.Cursor() == len(st.table.Rows())-1, " > ", "%s", "Done"),
	)
}

func (st stateChooseInPlacePatches) InfoView() string {
	v, _ := st.currentInfoView()
	return v.View()
}

func (st stateChooseInPlacePatches) updateTableRows(m Model) stateChooseInPlacePatches {
	// update the checkbox for each row
	rows := st.table.Rows()
	anySelected := false
	for i, pIdx := range st.patchIdx {
		// don't render a checkbox on the empty lines
		if rows[i+1][0] == "" {
			continue
		}
		var checkBox string
		if st.stateInPlace.selectedChanges[pIdx] {
			checkBox = "[x]"
			anySelected = true
		} else {
			checkBox = "[ ]"
		}
		rows[i+1][0] = fmt.Sprintf("%s %s", checkBox, m.lockfilePatches[pIdx].PackageUpdates[0].Name)
	}
	// show select all only if nothing is selected,
	// show deselect all if anything is selected
	if anySelected {
		rows[0][0] = "DESELECT ALL"
	} else {
		rows[0][0] = "SELECT ALL"
	}
	st.table.SetRows(rows)
	// there is no table.Columns() method, so I can't resize the columns to fit the checkbox properly :(
	return st
}

func (st stateChooseInPlacePatches) toggleSelection(idx int) stateChooseInPlacePatches {
	i := st.patchIdx[idx]
	st.stateInPlace.selectedChanges[i] = !st.stateInPlace.selectedChanges[i]
	return st
}

func (st stateChooseInPlacePatches) currentInfoView() (view components.ViewModel, canFocus bool) {
	if c := st.table.Cursor(); c > 0 && c < len(st.table.Rows())-1 {
		return st.vulnsInfos[c-1], true
	}

	return components.TextView(""), false
}

func (st stateChooseInPlacePatches) Resize(w, h int) modelState {
	st.viewWidth = w
	st.table.SetWidth(w)
	st.table.SetHeight(h - 1) // -1 to account for 'Done' line at bottom
	return st
}

func (st stateChooseInPlacePatches) ResizeInfo(w, h int) modelState {
	for i, info := range st.vulnsInfos {
		st.vulnsInfos[i] = info.Resize(w, h)
	}
	return st
}

func (st stateChooseInPlacePatches) IsInfoFocused() bool {
	return st.focusedInfo != nil
}
